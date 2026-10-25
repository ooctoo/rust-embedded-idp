"""Container runtime, startup refusal and compiled-resource gates for N2 H01."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import time
import struct
import urllib.error
import urllib.request
from prepare_management_n2_linux import Fixture, docker


def get(url):
    with urllib.request.urlopen(url, timeout=10) as response:
        return response.read()


def snapshot(fixture, extra_schemas=()):
    facts = {}
    for schema in [*fixture.state['schemas'].values(), *extra_schemas]:
        tables = fixture.sql("select tablename from pg_tables where schemaname='" + schema + "' order by tablename").splitlines()
        facts[schema] = {table: fixture.sql(f'select count(*) from {schema}."{table}"') for table in tables}
        # Only public synthetic client configuration; never password/refresh digests.
        facts[schema]['clientConfigurations'] = fixture.sql(f"select client_id,client_name,redirect_uris_json,client_type,pkce_required from {schema}.oidc_clients order by client_id")
    return facts


def check(fixture, output):
    cases = []
    def passed(name, details):
        cases.append({'name': name, **details})
        (output / 'results.json').write_text(json.dumps({'complete': False, 'cases': cases}, indent=2) + '\n')

    binary_path = fixture.directory / 'compiled-app'
    docker('cp', fixture.state['hosts']['enabled']['container'] + ':/app/embedded-idp-app', str(binary_path))
    binary = binary_path.read_bytes()
    assert binary[:4] == b'\x7fELF' and binary[4:6] == bytes([2, 1]) and struct.unpack_from('<H', binary, 18)[0] == 183
    passed('L01 actual runtime artifact is Linux ELF64 AArch64', {'elfMachine': 183, 'sha256': hashlib.sha256(binary).hexdigest()})

    for key, host in fixture.state['hosts'].items():
        resource = next(r for r in fixture.state['resources'] if r['name'] == host['container'])
        item = fixture.inspect_owned(resource)
        assert item['Config']['User'] == '10001:10001'
        assert item['HostConfig']['ReadonlyRootfs'] and item['HostConfig']['Init']
        assert item['HostConfig']['CapDrop'] == ['ALL']
        assert 'no-new-privileges' in item['HostConfig']['SecurityOpt']
        assert not any(e.startswith('EMBEDDED_IDP_') for e in item['Config']['Env'])
        assert all(m['RW'] is False for m in item['Mounts'] if m['Destination'] == '/run/idp')
        version = docker('exec', host['container'], '/bin/sh', '-ec',
                         'id; stat -c "%a %u %g" /run/idp/secrets/key.der; cat /etc/os-release; ldd /app/embedded-idp-app; sha256sum /app/embedded-idp-app; dpkg-query -W').stdout
        assert 'uid=10001' in version and 'ID=debian' in version and 'VERSION_CODENAME=bookworm' in version
        assert 'not found' not in version
        assert not any(docker('exec', host['container'], '/bin/sh', '-c', 'command -v ' + tool, check=False).returncode == 0
                       for tool in ['node', 'pnpm', 'cargo', 'rustc', 'gcc'])
        (output / (key + '-runtime.txt')).write_text(version)
    pg = json.loads(docker('container', 'inspect', fixture.state['container']).stdout)[0]
    assert not pg['HostConfig']['PortBindings']
    assert fixture.sql('show data_directory') == '/var/lib/postgresql/18/docker'
    auth_methods = fixture.sql("select distinct auth_method from pg_hba_file_rules where error is null order by auth_method").splitlines()
    assert auth_methods == ['scram-sha-256'], auth_methods
    passed('L02 nonroot, readonly, minimal runtime and private PG network', {'hostsChecked': 4, 'publishedPgPorts': 0, 'pgAuthenticationMethods': auth_methods})

    default = fixture.config('enabled', 'default', {'kind': 'fixed', 'tenant_id': '0'}, '/api', '/')
    default_host = fixture.launch('default', default)
    assert b'idp-browser-config' in get(default_host['origin'] + '/')
    assets = []
    for key in ['enabled', 'disabled', 'fixed', 'choose', 'default']:
        host = fixture.state['hosts'][key]
        html = get(host['origin'] + host['ui'] + ('/' if host['ui'] != '/' else '')).decode()
        assert html.count('name="idp-browser-config"') == 1
        import re
        for path in re.findall(r'(?:src|href)="([^\"]+\.(?:js|css))"', html):
            absolute = urllib.parse.urljoin(host['origin'] + host['ui'] + '/', path)
            data = get(absolute)
            assert data in binary, 'Served resource must be embedded byte-for-byte in the built ELF'
            assets.append({'entry': key, 'path': urllib.parse.urlsplit(absolute).path,
                           'sha256': hashlib.sha256(data).hexdigest(), 'embeddedInRuntimeElf': True})
    assert len(assets) >= 10
    assert len({a['sha256'] for a in assets if a['path'].endswith('.js')}) == 1
    (output / 'served-assets.json').write_text(json.dumps(assets, indent=2) + '\n')
    resource = next(r for r in fixture.state['resources'] if r['name'] == default_host['container'])
    fixture.remove_container(resource)
    passed('L03 default and nondefault compiled resources and unique trusted metadata', {'entries': 5, 'resourcesChecked': len(assets)})

    base = fixture.config('enabled', 'negative', {'kind': 'fixed', 'tenant_id': '0'})
    negatives = {}
    for name in ['missing-schema', 'missing-client', 'bad-key', 'key-permissions', 'source-conflict', 'unsupported-business', 'missing-admin']:
        config = copy.deepcopy(base)
        config['management']['login_entry'] = name
        config['management']['browser']['cookie_name'] = 'idp_negative_' + name.replace('-', '_')
        if name == 'missing-schema': config['runtime']['postgres']['connection']['schema_name'] = 'uib_absent_' + fixture.state['nonce']
        if name == 'missing-client': config['management']['client_id'] = 'absent-client'
        if name in ['bad-key', 'key-permissions']:
            fixture.once(['/bin/sh', '-ec', 'umask 077; ' + (
                'printf invalid > /run/idp/secrets/bad.der; chown 10001:10001 /run/idp/secrets/bad.der' if name == 'bad-key' else
                'cp /run/idp/secrets/key.der /run/idp/secrets/permissive.der; chmod 644 /run/idp/secrets/permissive.der')])
            config['runtime']['signing_key_file'] = '/run/idp/secrets/' + ('bad.der' if name == 'bad-key' else 'permissive.der')
        if name == 'unsupported-business':
            config['business_entries'] = [{'login_entry': 'business', 'client_id': 'business-client',
                'tenant_policy': {'kind': 'fixed', 'tenant_id': 'tenant-a'}, 'mount_prefix': '/business'}]
        if name == 'missing-admin':
            schema = 'uib_noadmin_' + fixture.state['nonce']
            fixture.once(['/app/bootstrap_local_postgres', '--access-schema'], env={
                'EMBEDDED_IDP_APP_PG_URI': fixture.state['db_uri'], 'EMBEDDED_IDP_APP_PG_SCHEMA': schema,
                'EMBEDDED_IDP_APP_PG_TLS_MODE': 'disable', 'EMBEDDED_IDP_APP_TENANCY_MODE': 'enabled'})
            config['runtime']['postgres']['connection']['schema_name'] = schema
        extra = [schema] if name == 'missing-admin' else []
        before = snapshot(fixture, extra)
        host = fixture.launch(name, config, ready=False, extra_env={
            'EMBEDDED_IDP_APP_BIND_ADDR': '127.0.0.1:9999'} if name == 'source-conflict' else None)
        resource = next(r for r in fixture.state['resources'] if r['name'] == host['container'])
        for _ in range(100):
            item = fixture.inspect_owned(resource)
            if not item['State']['Running']: break
            time.sleep(.1)
        assert not item['State']['Running'] and item['State']['ExitCode'] != 0, name
        try:
            get(host['origin'] + '/readyz')
            raise AssertionError('Unexpected readiness')
        except (urllib.error.URLError, ConnectionError): pass
        assert snapshot(fixture, extra) == before, name
        diagnostic = docker('logs', host['container']).stderr
        # Public startup errors should be stable messages, never raw config.
        for secret in [fixture.state['password'], fixture.state['db_uri'], fixture.state['db_password']]:
            assert secret not in diagnostic
        negatives[name] = {'exitCode': item['State']['ExitCode'], 'noListener': True,
                           'rowCountsAndClientConfigurationsUnchanged': True, 'diagnostic': diagnostic.strip()}
    passed('L04 startup refusals preserve sampled database facts', {'cases': negatives,
           'boundary': 'table counts and public client configuration snapshots; not a full database write audit'})
    (output / 'results.json').write_text(json.dumps({'complete': True, 'cases': cases}, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', required=True, type=Path); parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(); args.output.mkdir(exist_ok=False)
    check(Fixture.load(args.fixture), args.output)


if __name__ == '__main__': main()
