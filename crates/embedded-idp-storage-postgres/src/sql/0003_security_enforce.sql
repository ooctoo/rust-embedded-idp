select pg_advisory_lock(hashtext('__SCHEMA__:embedded-idp-migration'));

begin;

do $cutover$
begin
    if not exists (
        select 1 from __SCHEMA__.schema_versions where version = '0002_expand'
    ) then
        raise exception 'security cutover requires schema version 0002_expand';
    end if;

    if exists (
        select 1
        from __SCHEMA__.schema_versions
        where version not in ('0001', '0002_expand', '0003_enforce')
    ) then
        raise exception 'security cutover found an unsupported schema version';
    end if;

    if not exists (
        select 1 from __SCHEMA__.security_cutovers where cutover_id = 'production_security_v2'
    ) then
        update __SCHEMA__.auth_sessions
        set status = 'revoked'
        where status <> 'revoked';

        update __SCHEMA__.authorization_codes
        set consumed_at_epoch = extract(epoch from clock_timestamp())::bigint
        where consumed_at_epoch is null;

        delete from __SCHEMA__.refresh_tokens;
        delete from __SCHEMA__.device_nonces;

        update __SCHEMA__.devices
        set status = 'revoked'
        where status <> 'revoked';

        insert into __SCHEMA__.security_cutovers (cutover_id, completed_at_epoch)
        values ('production_security_v2', extract(epoch from clock_timestamp())::bigint);
    end if;
end
$cutover$;

alter table __SCHEMA__.device_nonces
    alter column purpose set not null;

alter table __SCHEMA__.device_nonces
    alter column challenge_digest set not null;

alter table __SCHEMA__.refresh_tokens
    alter column token_digest set not null;

do $constraints$
begin
    if not exists (
        select 1 from pg_constraint
        where conname = 'device_nonces_purpose_check'
          and conrelid = '__SCHEMA__.device_nonces'::regclass
    ) then
        alter table __SCHEMA__.device_nonces
            add constraint device_nonces_purpose_check
            check (purpose ~ '^[a-z][a-z0-9_]{0,63}$');
    end if;

    if not exists (
        select 1 from pg_constraint
        where conname = 'device_nonces_digest_length_check'
          and conrelid = '__SCHEMA__.device_nonces'::regclass
    ) then
        alter table __SCHEMA__.device_nonces
            add constraint device_nonces_digest_length_check
            check (octet_length(challenge_digest) = 32);
    end if;

    if not exists (
        select 1 from pg_constraint
        where conname = 'device_nonces_time_check'
          and conrelid = '__SCHEMA__.device_nonces'::regclass
    ) then
        alter table __SCHEMA__.device_nonces
            add constraint device_nonces_time_check
            check (
                expires_at_epoch > issued_at_epoch
                and (consumed_at_epoch is null or consumed_at_epoch >= issued_at_epoch)
            );
    end if;

    if not exists (
        select 1 from pg_constraint
        where conname = 'refresh_tokens_digest_length_check'
          and conrelid = '__SCHEMA__.refresh_tokens'::regclass
    ) then
        alter table __SCHEMA__.refresh_tokens
            add constraint refresh_tokens_digest_length_check
            check (octet_length(token_digest) = 32);
    end if;

    if not exists (
        select 1 from pg_constraint
        where conname = 'refresh_tokens_revocation_check'
          and conrelid = '__SCHEMA__.refresh_tokens'::regclass
    ) then
        alter table __SCHEMA__.refresh_tokens
            add constraint refresh_tokens_revocation_check
            check (
                (revoked_at_epoch is null and revocation_reason is null)
                or (
                    revoked_at_epoch is not null
                    and revocation_reason is not null
                    and revocation_reason in (
                        'rotated',
                        'reuse_detected',
                        'logout',
                        'client_revocation',
                        'administrative',
                        'security_cutover'
                    )
                )
            );
    end if;
end
$constraints$;

insert into __SCHEMA__.schema_versions (version, description, applied_at_epoch)
values ('0003_enforce', 'production security enforced schema', extract(epoch from clock_timestamp())::bigint)
on conflict (version) do nothing;

commit;

select pg_advisory_unlock(hashtext('__SCHEMA__:embedded-idp-migration'));
