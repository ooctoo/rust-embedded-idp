"""Owned Linux arm64 container fixtures for the existing Mac browser suites.

Never reads project .env files. All credentials and recovery state are private.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
import uuid

OWNER = 'idp.n2-linux.fixture'


def docker(*args, input=None, check=True):
    result = subprocess.run(['docker', *args], input=input, text=True, capture_output=True)
    if check and result.returncode:
        # Raw stderr may contain configuration, connection URIs or passwords.
        raise RuntimeError('Docker operation failed: ' + args[0])
    return result


def api(host, path, method='GET', data=None, token=None, target=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if target:
        headers['X-Embedded-Idp-Tenant-Id'] = target
    request = urllib.request.Request(host['origin'] + host['mount'] + '/admin' + path,
                                    data=None if data is None else json.dumps(data).encode(),
                                    headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response) if response.status != 204 else None


class Fixture:
    def __init__(self, state):
        self.state = state
        self.directory = Path(state['dir'])

    @classmethod
    def create(cls, runtime, prepare, postgres):
        if docker('context', 'show').stdout.strip() != 'desktop-linux':
            raise RuntimeError('Expected explicitly selected local desktop-linux context')
        daemon = docker('info', '--format', '{{.OSType}}/{{.Architecture}}').stdout.strip()
        if daemon not in ('linux/aarch64', 'linux/arm64'):
            raise RuntimeError('Native Linux arm64 daemon required')
        for image in [runtime, prepare, postgres]:
            item = json.loads(docker('image', 'inspect', image).stdout)[0]
            if item['Os'] != 'linux' or item['Architecture'] != 'arm64':
                raise RuntimeError('Linux arm64 image required')
        os.umask(0o077)
        directory = Path(tempfile.mkdtemp(prefix='idp-ui-b-')).resolve()
        nonce = uuid.uuid4().hex[:12]
        fixture = cls({'dir': str(directory), 'nonce': nonce, 'runtime': runtime,
                       'prepare': prepare, 'postgres': postgres, 'resources': [], 'hosts': {},
                       'schemas': {}, 'password': 'N2-' + uuid.uuid4().hex + 'aA!',
                       'db_password': uuid.uuid4().hex})
        fixture.save()
        return fixture

    @classmethod
    def load(cls, path):
        path = Path(path).resolve()
        state = json.loads(path.read_text())
        if (path.name != 'state.json' or path.parent != Path(state['dir']) or
                path.parent.parent != Path(tempfile.gettempdir()).resolve() or
                not re.fullmatch(r'idp-ui-b-[\w-]+', path.parent.name) or
                not re.fullmatch(r'[a-f0-9]{12}', state['nonce'])):
            raise ValueError('Not an owned Linux fixture state')
        return cls(state)

    def save(self):
        temporary = self.directory / 'state.next'
        with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'w') as stream:
            stream.write(json.dumps(self.state))
        temporary.replace(self.directory / 'state.json')

    def labels(self):
        return ['--label', OWNER + '=' + str(self.directory), '--label', 'idp.n2-linux.run=' + self.state['nonce']]

    def add(self, kind, name, args):
        resource = {'kind': kind, 'name': name}
        self.state['resources'].append(resource)
        self.save()  # Recovery survives a partial Docker create or lost response.
        result = docker(*args).stdout.strip()
        if kind == 'container':
            resource['id'] = result
        self.save()
        if kind == 'volume':
            # Docker volume create may return an existing volume. Verify its
            # owner before any preparation container can mount and write it.
            if self.inspect_owned(resource) is None:
                raise RuntimeError('Created volume is missing')
        return resource

    def inspect_owned(self, resource):
        kind, name = resource['kind'], resource['name']
        result = docker(kind, 'inspect', name, check=False)
        if result.returncode:
            # A failed inspect is not evidence of absence or a healthy daemon.
            args = ['container', 'ls', '-a', '--format', '{{.Names}}'] if kind == 'container' else [kind, 'ls', '--format', '{{.Name}}']
            names = docker(*args).stdout.splitlines()
            if name in names:
                raise ValueError('Existing resource ownership cannot be verified')
            return None
        item = json.loads(result.stdout)[0]
        labels = item.get('Labels') if kind != 'container' else item['Config'].get('Labels')
        if not labels or labels.get(OWNER) != str(self.directory) or labels.get('idp.n2-linux.run') != self.state['nonce']:
            raise ValueError('Resource ownership mismatch')
        if kind == 'container' and resource.get('id') and resource['id'] != item['Id']:
            raise ValueError('Container ID changed')
        return item

    def remove_container(self, resource):
        item = self.inspect_owned(resource)
        if item is None:
            return {'name': resource['name'], 'absent': True}
        if item['State']['Running']:
            docker('stop', '--time', '10', item['Id'])
            item = self.inspect_owned(resource)
        if item['State']['Running']:
            raise RuntimeError('Container did not stop')
        result = {'name': resource['name'], 'exitCode': item['State']['ExitCode'],
                  'oomKilled': item['State'].get('OOMKilled', False)}
        docker('rm', item['Id'])
        if self.inspect_owned(resource) is not None:
            raise RuntimeError('Container still exists')
        return result

    def cleanup(self, preserve_private=False):
        records, errors = [], []
        # Application/preparation containers first, PostgreSQL last.
        containers = [r for r in self.state['resources'] if r['kind'] == 'container']
        containers.sort(key=lambda r: r['name'] == self.state.get('container'))
        for resource in containers:
            if resource['name'] == self.state.get('container') and errors:
                continue
            try:
                result = self.remove_container(resource)
                records.append(result)
                if result.get('oomKilled') or result.get('exitCode') == 137:
                    errors.append({'name': resource['name'], 'error': 'UnexpectedForcedStop'})
            except Exception as error:
                errors.append({'name': resource['name'], 'error': type(error).__name__})
        if not errors:
            remaining = [r for r in self.state['resources'] if r['kind'] != 'container']
            for resource in sorted(remaining, key=lambda r: r['kind'] == 'network'):
                try:
                    if self.inspect_owned(resource) is not None:
                        docker(resource['kind'], 'rm', resource['name'])
                    if self.inspect_owned(resource) is not None:
                        raise RuntimeError('Resource still exists')
                    records.append({'name': resource['name'], 'removedOrAbsent': True})
                except Exception as error:
                    errors.append({'name': resource['name'], 'error': type(error).__name__})
        if not errors and not preserve_private:
            try:
                shutil.rmtree(self.directory)
            except OSError as error:
                errors.append({'resource': 'private-directory', 'error': type(error).__name__})
        return {'objects': records, 'errors': errors, 'privateDirectoryRemoved': not self.directory.exists()}

    def sql(self, statement):
        item = self.inspect_owned(next(r for r in self.state['resources'] if r['name'] == self.state['container']))
        if item is None:
            raise RuntimeError('Owned PostgreSQL container is missing')
        return docker('exec', '-i', item['Id'], 'psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1',
                      '-U', 'uib', '-d', 'uib', input=statement).stdout.strip()

    def once(self, command, input=None, env=None):
        name = 'idp-n2-linux-' + self.state['nonce'] + '-prepare-' + uuid.uuid4().hex[:6]
        args = ['container', 'create', '--pull=never', '--platform', 'linux/arm64', '--name', name,
                *self.labels(), '--network', self.state['network'], '--user', '0:0', '-i',
                '--mount', 'source=' + self.state['secrets_volume'] + ',target=/run/idp']
        if env:
            env_path = self.directory / 'prepare.env'
            env_path.write_text(''.join(k + '=' + v + '\n' for k, v in env.items()))
            args += ['--env-file', str(env_path)]
        args += ['--entrypoint', command[0], self.state['prepare'], *command[1:]]
        resource = self.add('container', name, args)
        result = docker('start', '-a', '-i', resource['id'], input=input, check=False)
        (self.directory / (name + '.log')).write_text(result.stdout + result.stderr)
        item = self.inspect_owned(resource)
        if result.returncode or item is None or item['State']['Running'] or item['State']['ExitCode'] != 0:
            raise RuntimeError('Preparation command failed: ' + command[0])
        self.remove_container(resource)
        return result.stdout.strip()

    def write_config(self, label, config):
        (self.directory / (label + '.json')).write_text(json.dumps(config))
        self.once(['/bin/sh', '-ec', 'umask 077; cat > /run/idp/' + label + '.json; chown 10001:10001 /run/idp/' + label + '.json'],
                  input=json.dumps(config))

    def launch(self, label, config, *, ready=True, extra_env=None):
        self.write_config(label, config)
        port = int(config['runtime']['http']['browser_origin'].rsplit(':', 1)[1])
        name = 'idp-n2-linux-' + self.state['nonce'] + '-' + label
        args = ['container', 'create', '--pull=never', '--platform', 'linux/arm64', '--name', name,
                *self.labels(), '--network', self.state['network'], '--init', '--read-only',
                '--user', '10001:10001', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m', '--stop-timeout', '10',
                *[part for key, value in (extra_env or {}).items() for part in ['--env', key + '=' + value]],
                '--mount', 'source=' + self.state['secrets_volume'] + ',target=/run/idp,readonly',
                '-p', '127.0.0.1:' + str(port) + ':8080', self.state['runtime'], '--config', '/run/idp/' + label + '.json']
        resource = self.add('container', name, args)
        host = {'label': label, 'origin': config['runtime']['http']['browser_origin'],
                'mount': config['management']['mount_prefix'], 'ui': config['management'].get('ui', {}).get('base_path', '/'),
                'cookie_name': config['management'].get('browser', {}).get('cookie_name'),
                'container': resource['name'], 'containerId': resource['id'], 'config': str(self.directory / (label + '.json'))}
        self.state['hosts'][label] = host
        self.save()
        docker('start', resource['id'])
        if ready:
            for _ in range(150):
                item = self.inspect_owned(resource)
                if not item['State']['Running']:
                    raise RuntimeError('App exited before readiness: ' + label)
                try:
                    with urllib.request.urlopen(host['origin'] + '/readyz', timeout=.5) as response:
                        if response.status == 200:
                            mapping = item['NetworkSettings']['Ports']['8080/tcp']
                            if mapping != [{'HostIp': '127.0.0.1', 'HostPort': str(port)}]:
                                raise ValueError('Unexpected published port')
                            return host
                except OSError:
                    time.sleep(.2)
            raise TimeoutError('App readiness timed out')
        return host

    def restart(self, label):
        host = self.state['hosts'][label]
        resource = next(r for r in self.state['resources'] if r['name'] == host['container'])
        config = json.loads(Path(host['config']).read_text())
        stopped = self.remove_container(resource)
        self.state.setdefault('restartAttempts', []).append(stopped)
        # The old ID was verified absent; a new ID with the same name is owned
        # by a new record rather than being mistaken for a reused original ID.
        self.state['resources'].remove(resource)
        self.save()
        if stopped.get('exitCode') in (137,) or stopped.get('oomKilled'):
            raise RuntimeError('Restart requires normal bounded stop, not a forced kill')
        self.launch(label, config)
        return {'stop': stopped, 'host': {k: host[k] for k in ['origin', 'mount', 'ui']}, 'sameOrigin': True}

    def config(self, mode, label, policy, mount='/identity', ui='/console'):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        origin = 'http://127.0.0.1:' + str(port)
        return {'version': 1, 'runtime': {'tenancy_mode': mode, 'bind_addr': '0.0.0.0:8080',
                'issuer': origin, 'signing_key_file': '/run/idp/secrets/key.der',
                'postgres': {'connection': {'uri_ref': {'file': '/run/idp/secrets/database-uri'},
                'schema_name': self.state['schemas'][mode], 'tls_mode': 'disable'},
                'pool': {'application_name': 'idp-n2-linux', 'max_connections': 4, 'connect_timeout_secs': 5}},
                'http': {'browser_origin': origin, 'transport_policy': 'default'}},
                'management': {'login_entry': label, 'client_id': 'management-ui-b', 'tenant_policy': policy,
                'mount_prefix': mount, 'browser': {'cookie_name': 'idp_ui_b_' + label}, 'ui': {'base_path': ui}},
                'business_entries': []}

    def prepare(self):
        nonce = self.state['nonce']
        self.state.update(network='idp-n2-linux-' + nonce, container='idp-ui-b-' + nonce,
                          data_volume='idp-n2-linux-' + nonce + '-data', secrets_volume='idp-n2-linux-' + nonce + '-secrets')
        self.save()
        self.add('network', self.state['network'], ['network', 'create', *self.labels(), self.state['network']])
        for name in [self.state['data_volume'], self.state['secrets_volume']]:
            self.add('volume', name, ['volume', 'create', *self.labels(), name])
        env_path = self.directory / 'postgres.env'
        env_path.write_text('POSTGRES_USER=uib\nPOSTGRES_DB=uib\nPOSTGRES_PASSWORD=' + self.state['db_password'] +
                            '\nPGPASSWORD=' + self.state['db_password'] +
                            '\nPOSTGRES_INITDB_ARGS=--auth-local=scram-sha-256 --auth-host=scram-sha-256\n')
        self.add('container', self.state['container'], ['container', 'create', '--pull=never', '--platform', 'linux/arm64',
                 '--name', self.state['container'], *self.labels(), '--label', 'idp.ui-b.fixture=' + str(self.directory),
                 '--network', self.state['network'], '--env-file', str(env_path),
                 '--mount', 'source=' + self.state['data_volume'] + ',target=/var/lib/postgresql', self.state['postgres']])
        docker('start', self.state['container'])
        for _ in range(150):
            if docker('exec', self.state['container'], 'pg_isready', '-h', '127.0.0.1', '-U', 'uib', '-d', 'uib', check=False).returncode == 0:
                break
            time.sleep(.2)
        self.state['pg_version'] = self.sql('show server_version')
        if not self.state['pg_version'].startswith('18.6'):
            raise ValueError('PostgreSQL 18.6 required')
        self.state['db_uri'] = 'postgresql://uib:' + self.state['db_password'] + '@' + self.state['container'] + ':5432/uib'
        self.once(['/bin/sh', '-ec', 'umask 077; mkdir -p /run/idp/secrets; openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -outform DER -out /run/idp/secrets/key.der; cat > /run/idp/secrets/database-uri; chown -R 10001:10001 /run/idp; chmod 700 /run/idp/secrets'], input=self.state['db_uri'])
        for mode in ['enabled', 'disabled']:
            schema = 'uib_' + mode + '_' + uuid.uuid4().hex[:10]
            self.state['schemas'][mode] = schema; self.save()
            env = {'EMBEDDED_IDP_APP_PG_URI': self.state['db_uri'], 'EMBEDDED_IDP_APP_PG_SCHEMA': schema,
                   'EMBEDDED_IDP_APP_PG_TLS_MODE': 'disable', 'EMBEDDED_IDP_APP_TENANCY_MODE': mode}
            self.once(['/app/bootstrap_local_postgres', '--access-schema'], env=env)
            self.once(['/app/embedded-idp-app', 'bootstrap-admin', '--email', 'admin@example.test', '--password-stdin'],
                      env=env, input=self.state['password'] + '\n')
            self.sql(f"insert into {schema}.oidc_clients(client_id,client_name,redirect_uris_json,client_type,pkce_required,created_at_epoch) values ('management-ui-b','UI B management','[\"http://127.0.0.1/callback\"]','public_desktop',true,1)")
            self.launch(mode, self.config(mode, mode, {'kind': 'fixed', 'tenant_id': '0'},
                        '/identity' if mode == 'enabled' else '/gateway', '/console' if mode == 'enabled' else '/manage'))
        enabled = self.state['hosts']['enabled']
        tokens = api(enabled, '/auth/login', 'POST', {'email': 'admin@example.test', 'password': self.state['password']})['tokens']
        token = tokens['access_token']
        for tenant in ['tenant-a', 'tenant-b', '.', '..']:
            api(enabled, '/tenants', 'POST', {'tenant_id': tenant, 'name': 'UI B ' + tenant, 'allow_registration': False,
                'administrator': {'kind': 'new', 'email': {'.': 'dot@example.test', '..': 'dotdot@example.test'}.get(tenant, tenant + '@example.test'), 'password': self.state['password']}}, token)
        subject = api(enabled, '/accounts', token=token, target='tenant-a')['items'][0]['account_id']
        for tenant in ['tenant-b', '.', '..']:
            api(enabled, '/members/' + subject + '/bind', 'POST', {}, token, tenant)
            api(enabled, '/access/security-admins/' + subject, 'POST', None, token, tenant)
        self.launch('fixed', self.config('enabled', 'fixed', {'kind': 'fixed', 'tenant_id': 'tenant-a'}))
        self.launch('choose', self.config('enabled', 'choose', {'kind': 'choose'}))
        api(enabled, '/auth/logout', 'POST', token=token)
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime'); parser.add_argument('--prepare'); parser.add_argument('--postgres')
    parser.add_argument('--cleanup', type=Path); parser.add_argument('--cleanup-output', type=Path)
    parser.add_argument('--restart', type=Path); parser.add_argument('--label', default='enabled')
    args = parser.parse_args()
    if args.restart:
        print(json.dumps(Fixture.load(args.restart).restart(args.label)))
        return 0
    if args.cleanup:
        result = Fixture.load(args.cleanup).cleanup()
        if args.cleanup_output:
            args.cleanup_output.write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result))
        return 1 if result['errors'] else 0
    if not all([args.runtime, args.prepare, args.postgres]):
        parser.error('--runtime, --prepare and --postgres are required')
    fixture = Fixture.create(args.runtime, args.prepare, args.postgres)
    try:
        fixture.prepare()
        print(json.dumps({'fixture_file': str(fixture.directory / 'state.json'),
                          'postgres_version': fixture.state['pg_version'],
                          'hosts': {k: v['origin'] + v['ui'] + '/' for k, v in fixture.state['hosts'].items()}}))
    except BaseException as error:
        fixture.save()
        # Keep private diagnostics/recovery and let the owning runner clean up.
        (fixture.directory / 'failure.txt').write_text(type(error).__name__ + ': ' + str(error))
        print(json.dumps({'fixture_file': str(fixture.directory / 'state.json'), 'error': type(error).__name__}))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
