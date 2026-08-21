use std::time::{Duration, SystemTime, UNIX_EPOCH};

use embedded_idp_core::{
    Account, AccountDeviceBinding, AccountDeviceBindingStatus, AccountDeviceBindingStore,
    AccountListQuery, AccountStatus, AccountStore, AuthSession, AuthorizationCodeRecord,
    AuthorizationCodeStore, ClientListQuery, ClientStore, DeviceListQuery, DeviceNonceRecord,
    DeviceNonceStore, DeviceProofAlgorithm, DeviceProofChallengeRecord, DeviceProofKeyRecord,
    DeviceProofKeyStatus, DeviceProofPurpose, DeviceRecord, DeviceRequestVerificationTransaction,
    DeviceSecurityTransaction, DeviceStatus, DeviceStore, EmailVerificationCode,
    EmailVerificationStore, OidcClient, OidcClientType, PkceChallengeMethod,
    ProofBoundRefreshTransaction, RefreshTokenRecord, RefreshTokenRevocationReason,
    RefreshTokenStore, SessionListQuery, SessionStatus, SessionStore, StoreError,
};
use postgres::{Row, Transaction};
use uuid::Uuid;

pub struct PostgresStoreTransaction<'a> {
    schema_name: &'a str,
    tx: Option<Transaction<'a>>,
}

impl<'a> PostgresStoreTransaction<'a> {
    pub fn new(schema_name: &'a str, tx: Transaction<'a>) -> Self {
        Self {
            schema_name,
            tx: Some(tx),
        }
    }

    pub fn into_inner(mut self) -> Option<Transaction<'a>> {
        self.tx.take()
    }

    fn tx_mut(&mut self) -> &mut Transaction<'a> {
        self.tx
            .as_mut()
            .expect("postgres transaction should still be active")
    }

    fn query_account_by_id_sql(&self) -> String {
        format!(
            "select id, email, password_hash, display_name, status, created_at_epoch \
             from {}.accounts where id = $1::uuid limit 1",
            self.schema_name
        )
    }

    fn query_accounts_by_email_sql(&self) -> String {
        format!(
            "select id, email, password_hash, display_name, status, created_at_epoch \
             from {}.accounts where email = $1 limit 1",
            self.schema_name
        )
    }

    fn list_accounts_sql(&self) -> String {
        format!(
            "select id, email, password_hash, display_name, status, created_at_epoch \
             from {}.accounts order by created_at_epoch desc, id asc",
            self.schema_name
        )
    }

    fn list_accounts_by_query_sql(&self) -> String {
        format!(
            "select id, email, password_hash, display_name, status, created_at_epoch \
             from {}.accounts \
             where ($1::text is null or status = $1) \
               and ($2::text is null or email ilike $2) \
               and ($3::bigint is null or created_at_epoch >= $3) \
               and ($4::bigint is null or created_at_epoch <= $4) \
               and ($5::bigint is null or created_at_epoch < $5 or (created_at_epoch = $5 and id > $6::uuid)) \
             order by created_at_epoch desc, id asc \
             limit $7 offset $8",
            self.schema_name
        )
    }

    fn count_accounts_by_query_sql(&self) -> String {
        format!(
            "select count(*) \
             from {}.accounts \
             where ($1::text is null or status = $1) \
               and ($2::text is null or email ilike $2) \
               and ($3::bigint is null or created_at_epoch >= $3) \
               and ($4::bigint is null or created_at_epoch <= $4)",
            self.schema_name
        )
    }

    fn insert_account_sql(&self) -> String {
        format!(
            "insert into {}.accounts \
             (id, email, password_hash, display_name, status, created_at_epoch) \
             values ($1::uuid, $2, $3, $4, $5, $6) \
             returning id, email, password_hash, display_name, status, created_at_epoch",
            self.schema_name
        )
    }

    fn update_account_sql(&self) -> String {
        format!(
            "update {}.accounts \
             set email = $2, password_hash = $3, display_name = $4, status = $5 \
             where id = $1::uuid \
             returning id, email, password_hash, display_name, status, created_at_epoch",
            self.schema_name
        )
    }

    fn query_session_by_id_sql(&self) -> String {
        format!(
            "select id, account_id, client_id, device_id, status, created_at_epoch, expires_at_epoch, refresh_token_version \
             from {}.auth_sessions where id = $1::uuid limit 1",
            self.schema_name
        )
    }

    fn list_sessions_sql(&self) -> String {
        format!(
            "select id, account_id, client_id, device_id, status, created_at_epoch, expires_at_epoch, refresh_token_version \
             from {}.auth_sessions order by created_at_epoch desc, id asc",
            self.schema_name
        )
    }

    fn list_sessions_by_account_sql(&self) -> String {
        format!(
            "select id, account_id, client_id, device_id, status, created_at_epoch, expires_at_epoch, refresh_token_version \
             from {}.auth_sessions where account_id = $1::uuid order by created_at_epoch desc, id asc",
            self.schema_name
        )
    }

    fn list_sessions_by_query_sql(&self) -> String {
        format!(
            "select id, account_id, client_id, device_id, status, created_at_epoch, expires_at_epoch, refresh_token_version \
             from {}.auth_sessions \
             where ($1::uuid is null or account_id = $1::uuid) \
               and ($2::text is null or status = $2) \
               and ($3::text is null or client_id = $3) \
               and ($4::uuid is null or device_id = $4::uuid) \
               and ($5::bigint is null or created_at_epoch >= $5) \
               and ($6::bigint is null or created_at_epoch <= $6) \
               and ($7::bigint is null or created_at_epoch < $7 or (created_at_epoch = $7 and id > $8::uuid)) \
             order by created_at_epoch desc, id asc \
             limit $9 offset $10",
            self.schema_name
        )
    }

    fn count_sessions_by_query_sql(&self) -> String {
        format!(
            "select count(*) \
             from {}.auth_sessions \
             where ($1::uuid is null or account_id = $1::uuid) \
               and ($2::text is null or status = $2) \
               and ($3::text is null or client_id = $3) \
               and ($4::uuid is null or device_id = $4::uuid) \
               and ($5::bigint is null or created_at_epoch >= $5) \
               and ($6::bigint is null or created_at_epoch <= $6)",
            self.schema_name
        )
    }

    fn insert_session_sql(&self) -> String {
        format!(
            "insert into {}.auth_sessions \
             (id, account_id, client_id, device_id, status, created_at_epoch, expires_at_epoch, refresh_token_version) \
             values ($1::uuid, $2::uuid, $3, $4::uuid, $5, $6, $7, $8) \
             returning id, account_id, client_id, device_id, status, created_at_epoch, expires_at_epoch, refresh_token_version",
            self.schema_name
        )
    }

    fn update_session_sql(&self) -> String {
        format!(
            "update {}.auth_sessions \
             set status = $2, device_id = $3::uuid, expires_at_epoch = $4, refresh_token_version = $5 \
             where id = $1::uuid \
             returning id, account_id, client_id, device_id, status, created_at_epoch, expires_at_epoch, refresh_token_version",
            self.schema_name
        )
    }

    fn query_device_by_id_sql(&self) -> String {
        format!(
            "select id, client_id, device_name, proof_key_id, status, registered_at_epoch, last_seen_at_epoch \
             from {}.devices where id = $1::uuid limit 1",
            self.schema_name
        )
    }

    fn list_devices_sql(&self) -> String {
        format!(
            "select id, client_id, device_name, proof_key_id, status, registered_at_epoch, last_seen_at_epoch \
             from {}.devices order by registered_at_epoch desc, id asc",
            self.schema_name
        )
    }

    fn list_devices_by_query_sql(&self) -> String {
        format!(
            "select distinct d.id, d.client_id, d.device_name, d.proof_key_id, d.status, d.registered_at_epoch, d.last_seen_at_epoch \
             from {}.devices d \
             left join {}.account_device_bindings adb \
               on adb.device_id = d.id and adb.status = 'active' \
             where ($1::uuid is null or adb.account_id = $1::uuid) \
               and ($2::text is null or d.client_id = $2) \
               and ($3::text is null or d.status = $3) \
               and ($4::bigint is null or d.registered_at_epoch >= $4) \
               and ($5::bigint is null or d.registered_at_epoch <= $5) \
               and ($6::bigint is null or d.registered_at_epoch < $6 or (d.registered_at_epoch = $6 and d.id > $7::uuid)) \
             order by d.registered_at_epoch desc, d.id asc \
             limit $8 offset $9",
            self.schema_name, self.schema_name
        )
    }

    fn count_devices_by_query_sql(&self) -> String {
        format!(
            "select count(distinct d.id) \
             from {}.devices d \
             left join {}.account_device_bindings adb \
               on adb.device_id = d.id and adb.status = 'active' \
             where ($1::uuid is null or adb.account_id = $1::uuid) \
               and ($2::text is null or d.client_id = $2) \
               and ($3::text is null or d.status = $3) \
               and ($4::bigint is null or d.registered_at_epoch >= $4) \
               and ($5::bigint is null or d.registered_at_epoch <= $5)",
            self.schema_name, self.schema_name
        )
    }

    fn query_device_by_proof_key_id_sql(&self) -> String {
        format!(
            "select id, client_id, device_name, proof_key_id, status, registered_at_epoch, last_seen_at_epoch \
             from {}.devices where proof_key_id = $1 limit 1",
            self.schema_name
        )
    }

    fn insert_device_sql(&self) -> String {
        format!(
            "insert into {}.devices \
             (id, client_id, device_name, proof_key_id, status, registered_at_epoch, last_seen_at_epoch) \
             values ($1::uuid, $2, $3, $4, $5, $6, $7) \
             returning id, client_id, device_name, proof_key_id, status, registered_at_epoch, last_seen_at_epoch",
            self.schema_name
        )
    }

    fn update_device_sql(&self) -> String {
        format!(
            "update {}.devices \
             set device_name = $2, proof_key_id = $3, status = $4, last_seen_at_epoch = $5 \
             where id = $1::uuid \
             returning id, client_id, device_name, proof_key_id, status, registered_at_epoch, last_seen_at_epoch",
            self.schema_name
        )
    }

    fn query_active_account_device_binding_sql(&self) -> String {
        format!(
            "select id, account_id, device_id, status, bound_at_epoch, unbound_at_epoch, last_authenticated_at_epoch \
             from {}.account_device_bindings \
             where account_id = $1::uuid and device_id = $2::uuid and status = 'active' limit 1",
            self.schema_name
        )
    }

    fn list_account_device_bindings_by_device_sql(&self) -> String {
        format!(
            "select id, account_id, device_id, status, bound_at_epoch, unbound_at_epoch, last_authenticated_at_epoch \
             from {}.account_device_bindings \
             where device_id = $1::uuid order by bound_at_epoch desc, id asc",
            self.schema_name
        )
    }

    fn list_active_account_device_bindings_by_account_sql(&self) -> String {
        format!(
            "select id, account_id, device_id, status, bound_at_epoch, unbound_at_epoch, last_authenticated_at_epoch \
             from {}.account_device_bindings \
             where account_id = $1::uuid and status = 'active' order by bound_at_epoch desc, id asc",
            self.schema_name
        )
    }

    fn insert_account_device_binding_sql(&self) -> String {
        format!(
            "insert into {}.account_device_bindings \
             (id, account_id, device_id, status, bound_at_epoch, unbound_at_epoch, last_authenticated_at_epoch) \
             values ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7) \
             returning id, account_id, device_id, status, bound_at_epoch, unbound_at_epoch, last_authenticated_at_epoch",
            self.schema_name
        )
    }

    fn update_account_device_binding_sql(&self) -> String {
        format!(
            "update {}.account_device_bindings \
             set status = $2, unbound_at_epoch = $3, last_authenticated_at_epoch = $4 \
             where id = $1::uuid \
             returning id, account_id, device_id, status, bound_at_epoch, unbound_at_epoch, last_authenticated_at_epoch",
            self.schema_name
        )
    }

    fn query_client_by_id_sql(&self) -> String {
        format!(
            "select client_id, client_name, redirect_uris_json, client_type, pkce_required, client_secret_hash \
             from {}.oidc_clients where client_id = $1 limit 1",
            self.schema_name
        )
    }

    fn list_clients_sql(&self) -> String {
        format!(
            "select client_id, client_name, redirect_uris_json, client_type, pkce_required, client_secret_hash \
             from {}.oidc_clients order by client_id asc",
            self.schema_name
        )
    }

    fn list_clients_by_query_sql(&self) -> String {
        format!(
            "select client_id, client_name, redirect_uris_json, client_type, pkce_required, client_secret_hash \
             from {}.oidc_clients \
             where ($1::text is null or client_type = $1) \
               and ($2::bool is null or pkce_required = $2) \
             order by client_id asc \
             limit $3 offset $4",
            self.schema_name
        )
    }

    fn count_clients_by_query_sql(&self) -> String {
        format!(
            "select count(*) \
             from {}.oidc_clients \
             where ($1::text is null or client_type = $1) \
               and ($2::bool is null or pkce_required = $2)",
            self.schema_name
        )
    }

    fn upsert_client_sql(&self) -> String {
        format!(
            "insert into {}.oidc_clients \
             (client_id, client_name, redirect_uris_json, client_type, pkce_required, client_secret_hash, created_at_epoch) \
             values ($1, $2, $3, $4, $5, $6, $7) \
             on conflict (client_id) do update set \
               client_name = excluded.client_name, \
               redirect_uris_json = excluded.redirect_uris_json, \
               client_type = excluded.client_type, \
               pkce_required = excluded.pkce_required, \
               client_secret_hash = excluded.client_secret_hash \
             returning client_id, client_name, redirect_uris_json, client_type, pkce_required, client_secret_hash",
            self.schema_name
        )
    }

    fn query_authorization_code_sql(&self) -> String {
        format!(
            "select code, account_id, client_id, redirect_uri, scope, nonce, code_challenge, \
             code_challenge_method, created_at_epoch, expires_at_epoch, consumed_at_epoch \
             from {}.authorization_codes where code = $1 limit 1",
            self.schema_name
        )
    }

    fn insert_authorization_code_sql(&self) -> String {
        format!(
            "insert into {}.authorization_codes \
             (code, account_id, client_id, redirect_uri, scope, nonce, code_challenge, \
             code_challenge_method, created_at_epoch, expires_at_epoch, consumed_at_epoch) \
             values ($1, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             returning code, account_id, client_id, redirect_uri, scope, nonce, code_challenge, \
             code_challenge_method, created_at_epoch, expires_at_epoch, consumed_at_epoch",
            self.schema_name
        )
    }

    fn consume_authorization_code_sql(&self) -> String {
        format!(
            "update {}.authorization_codes \
             set consumed_at_epoch = $2 \
             where code = $1 and consumed_at_epoch is null \
             returning code, account_id, client_id, redirect_uri, scope, nonce, code_challenge, \
             code_challenge_method, created_at_epoch, expires_at_epoch, consumed_at_epoch",
            self.schema_name
        )
    }

    fn query_email_verification_code_sql(&self) -> String {
        format!(
            "select id, account_id, email, code, issued_at_epoch, expires_at_epoch, consumed_at_epoch \
             from {}.email_verification_codes \
             where email = $1 and code = $2 \
             order by issued_at_epoch desc, id desc \
             limit 1",
            self.schema_name
        )
    }

    fn insert_email_verification_code_sql(&self) -> String {
        format!(
            "insert into {}.email_verification_codes \
             (id, account_id, email, code, issued_at_epoch, expires_at_epoch, consumed_at_epoch) \
             values ($1::uuid, $2::uuid, $3, $4, $5, $6, $7) \
             returning id, account_id, email, code, issued_at_epoch, expires_at_epoch, consumed_at_epoch",
            self.schema_name
        )
    }

    fn consume_email_verification_code_sql(&self) -> String {
        format!(
            "update {}.email_verification_codes \
             set consumed_at_epoch = $2 \
             where id = $1::uuid and consumed_at_epoch is null \
             returning id, account_id, email, code, issued_at_epoch, expires_at_epoch, consumed_at_epoch",
            self.schema_name
        )
    }

    fn consume_email_verification_codes_for_account_sql(&self) -> String {
        format!(
            "update {}.email_verification_codes \
             set consumed_at_epoch = $2 \
             where account_id = $1::uuid and consumed_at_epoch is null \
             returning id, account_id, email, code, issued_at_epoch, expires_at_epoch, consumed_at_epoch",
            self.schema_name
        )
    }

    fn query_refresh_token_sql(&self) -> String {
        format!(
            "select id, session_id, token_digest, token_version, issued_at_epoch, expires_at_epoch, revoked_at_epoch, revocation_reason \
             from {}.refresh_tokens where token_digest = $1 limit 1 for update",
            self.schema_name
        )
    }

    fn query_device_nonce_sql(&self) -> String {
        format!(
            "select id, device_id, challenge, issued_at_epoch, expires_at_epoch, consumed_at_epoch \
             from {}.device_nonces where challenge = $1 limit 1",
            self.schema_name
        )
    }

    fn insert_device_nonce_sql(&self) -> String {
        format!(
            "insert into {}.device_nonces \
             (id, device_id, challenge, issued_at_epoch, expires_at_epoch, consumed_at_epoch) \
             values ($1::uuid, $2::uuid, $3, $4, $5, $6) \
             returning id, device_id, challenge, issued_at_epoch, expires_at_epoch, consumed_at_epoch",
            self.schema_name
        )
    }

    fn consume_device_nonce_sql(&self) -> String {
        format!(
            "update {}.device_nonces \
             set consumed_at_epoch = $2 \
             where challenge = $1 and consumed_at_epoch is null \
             returning id, device_id, challenge, issued_at_epoch, expires_at_epoch, consumed_at_epoch",
            self.schema_name
        )
    }

    fn insert_refresh_token_sql(&self) -> String {
        format!(
            "insert into {}.refresh_tokens \
             (id, session_id, token_value, token_digest, token_version, issued_at_epoch, expires_at_epoch, revoked_at_epoch, revocation_reason) \
             values ($1::uuid, $2::uuid, null, $3, $4, $5, $6, $7, $8) \
             returning id, session_id, token_digest, token_version, issued_at_epoch, expires_at_epoch, revoked_at_epoch, revocation_reason",
            self.schema_name
        )
    }

    fn revoke_refresh_token_sql(&self) -> String {
        format!(
            "update {}.refresh_tokens \
             set revocation_reason = $2, revoked_at_epoch = $3 \
             where token_digest = $1 and revoked_at_epoch is null \
             returning id, session_id, token_digest, token_version, issued_at_epoch, expires_at_epoch, revoked_at_epoch, revocation_reason",
            self.schema_name
        )
    }

    fn revoke_refresh_tokens_for_session_sql(&self) -> String {
        format!(
            "update {}.refresh_tokens \
             set revocation_reason = $2, revoked_at_epoch = $3 \
             where session_id = $1::uuid and revoked_at_epoch is null \
             returning id, session_id, token_digest, token_version, issued_at_epoch, expires_at_epoch, revoked_at_epoch, revocation_reason",
            self.schema_name
        )
    }
}

impl AccountStore for PostgresStoreTransaction<'_> {
    fn find_account(&mut self, account_id: &str) -> Result<Option<Account>, StoreError> {
        let account_id = parse_uuid(account_id, "account.id")?;
        let sql = self.query_account_by_id_sql();
        let row = self
            .tx_mut()
            .query_opt(&sql, &[&account_id])
            .map_err(|error| StoreError::Backend(format!("query account by id failed: {error}")))?;
        row.map(decode_account).transpose()
    }

    fn list_accounts(&mut self) -> Result<Vec<Account>, StoreError> {
        let sql = self.list_accounts_sql();
        let rows = self
            .tx_mut()
            .query(&sql, &[])
            .map_err(|error| StoreError::Backend(format!("list accounts failed: {error}")))?;
        rows.into_iter().map(decode_account).collect()
    }

    fn list_accounts_by_query(
        &mut self,
        query: &AccountListQuery,
    ) -> Result<Vec<Account>, StoreError> {
        let sql = self.list_accounts_by_query_sql();
        let email_filter = query.email.as_ref().map(|value| format!("%{value}%"));
        let status = query.status.as_ref().map(encode_account_status);
        let created_after = query.created_after.map(to_epoch_secs);
        let created_before = query.created_before.map(to_epoch_secs);
        let cursor_time = query
            .cursor
            .as_ref()
            .map(|cursor| to_epoch_secs(cursor.sort_time));
        let cursor_id = query
            .cursor
            .as_ref()
            .map(|cursor| parse_uuid(&cursor.entity_id, "account.cursor_id"))
            .transpose()?;
        let rows = self
            .tx_mut()
            .query(
                &sql,
                &[
                    &status,
                    &email_filter,
                    &created_after,
                    &created_before,
                    &cursor_time,
                    &cursor_id,
                    &query.page.fetch_limit(),
                    &query.page.sql_offset(),
                ],
            )
            .map_err(|error| {
                StoreError::Backend(format!("list accounts by query failed: {error}"))
            })?;
        rows.into_iter().map(decode_account).collect()
    }

    fn count_accounts_by_query(&mut self, query: &AccountListQuery) -> Result<u64, StoreError> {
        let sql = self.count_accounts_by_query_sql();
        let email_filter = query.email.as_ref().map(|value| format!("%{value}%"));
        let status = query.status.as_ref().map(encode_account_status);
        let created_after = query.created_after.map(to_epoch_secs);
        let created_before = query.created_before.map(to_epoch_secs);
        let count: i64 = self
            .tx_mut()
            .query_one(
                &sql,
                &[&status, &email_filter, &created_after, &created_before],
            )
            .map_err(|error| {
                StoreError::Backend(format!("count accounts by query failed: {error}"))
            })?
            .get(0);
        Ok(count.max(0) as u64)
    }

    fn find_by_email(&mut self, email: &str) -> Result<Option<Account>, StoreError> {
        let sql = self.query_accounts_by_email_sql();
        let row = self.tx_mut().query_opt(&sql, &[&email]).map_err(|error| {
            StoreError::Backend(format!("query account by email failed: {error}"))
        })?;
        row.map(decode_account).transpose()
    }

    fn insert_account(&mut self, account: Account) -> Result<Account, StoreError> {
        let account_id = parse_uuid(&account.id, "account.id")?;
        let sql = self.insert_account_sql();
        let row = self
            .tx_mut()
            .query_one(
                &sql,
                &[
                    &account_id,
                    &account.email,
                    &account.password_hash,
                    &account.display_name,
                    &encode_account_status(&account.status),
                    &to_epoch_secs(account.created_at),
                ],
            )
            .map_err(map_write_error("insert account", Some("account.email")))?;
        decode_account(row)
    }

    fn update_account(&mut self, account: Account) -> Result<Account, StoreError> {
        let account_id = parse_uuid(&account.id, "account.id")?;
        let sql = self.update_account_sql();
        let row = self
            .tx_mut()
            .query_one(
                &sql,
                &[
                    &account_id,
                    &account.email,
                    &account.password_hash,
                    &account.display_name,
                    &encode_account_status(&account.status),
                ],
            )
            .map_err(map_write_error("update account", Some("account.email")))?;
        decode_account(row)
    }
}

impl SessionStore for PostgresStoreTransaction<'_> {
    fn find_session(&mut self, session_id: &str) -> Result<Option<AuthSession>, StoreError> {
        let session_id = parse_uuid(session_id, "auth_session.id")?;
        let sql = self.query_session_by_id_sql();
        let row = self
            .tx_mut()
            .query_opt(&sql, &[&session_id])
            .map_err(|error| StoreError::Backend(format!("query session by id failed: {error}")))?;
        row.map(decode_session).transpose()
    }

    fn list_sessions(&mut self, account_id: Option<&str>) -> Result<Vec<AuthSession>, StoreError> {
        let rows = match account_id {
            Some(account_id) => {
                let account_id = parse_uuid(account_id, "account.id")?;
                let sql = self.list_sessions_by_account_sql();
                self.tx_mut().query(&sql, &[&account_id]).map_err(|error| {
                    StoreError::Backend(format!("list sessions by account failed: {error}"))
                })?
            }
            None => {
                let sql = self.list_sessions_sql();
                self.tx_mut().query(&sql, &[]).map_err(|error| {
                    StoreError::Backend(format!("list sessions failed: {error}"))
                })?
            }
        };

        rows.into_iter().map(decode_session).collect()
    }

    fn list_sessions_by_query(
        &mut self,
        query: &SessionListQuery,
    ) -> Result<Vec<AuthSession>, StoreError> {
        let account_id = query
            .account_id
            .as_deref()
            .map(|value| parse_uuid(value, "account.id"))
            .transpose()?;
        let device_id = query.device_id.as_deref().map(parse_uuid_opt).transpose()?;
        let status = query.status.as_ref().map(encode_session_status);
        let created_after = query.created_after.map(to_epoch_secs);
        let created_before = query.created_before.map(to_epoch_secs);
        let cursor_time = query
            .cursor
            .as_ref()
            .map(|cursor| to_epoch_secs(cursor.sort_time));
        let cursor_id = query
            .cursor
            .as_ref()
            .map(|cursor| parse_uuid(&cursor.entity_id, "session.cursor_id"))
            .transpose()?;
        let sql = self.list_sessions_by_query_sql();
        let rows = self
            .tx_mut()
            .query(
                &sql,
                &[
                    &account_id,
                    &status,
                    &query.client_id,
                    &device_id,
                    &created_after,
                    &created_before,
                    &cursor_time,
                    &cursor_id,
                    &query.page.fetch_limit(),
                    &query.page.sql_offset(),
                ],
            )
            .map_err(|error| {
                StoreError::Backend(format!("list sessions by query failed: {error}"))
            })?;
        rows.into_iter().map(decode_session).collect()
    }

    fn count_sessions_by_query(&mut self, query: &SessionListQuery) -> Result<u64, StoreError> {
        let account_id = query
            .account_id
            .as_deref()
            .map(|value| parse_uuid(value, "account.id"))
            .transpose()?;
        let device_id = query.device_id.as_deref().map(parse_uuid_opt).transpose()?;
        let status = query.status.as_ref().map(encode_session_status);
        let created_after = query.created_after.map(to_epoch_secs);
        let created_before = query.created_before.map(to_epoch_secs);
        let sql = self.count_sessions_by_query_sql();
        let count: i64 = self
            .tx_mut()
            .query_one(
                &sql,
                &[
                    &account_id,
                    &status,
                    &query.client_id,
                    &device_id,
                    &created_after,
                    &created_before,
                ],
            )
            .map_err(|error| {
                StoreError::Backend(format!("count sessions by query failed: {error}"))
            })?
            .get(0);
        Ok(count.max(0) as u64)
    }

    fn insert_session(&mut self, session: AuthSession) -> Result<AuthSession, StoreError> {
        let session_id = parse_uuid(&session.id, "auth_session.id")?;
        let account_id = parse_uuid(&session.account_id, "account.id")?;
        let sql = self.insert_session_sql();
        let row = self
            .tx_mut()
            .query_one(
                &sql,
                &[
                    &session_id,
                    &account_id,
                    &session.client_id,
                    &session
                        .device_id
                        .as_deref()
                        .map(parse_uuid_opt)
                        .transpose()?,
                    &encode_session_status(&session.status),
                    &to_epoch_secs(session.created_at),
                    &to_epoch_secs(session.expires_at),
                    &(session.refresh_token_version as i64),
                ],
            )
            .map_err(map_write_error("insert session", Some("auth_session.id")))?;
        decode_session(row)
    }

    fn update_session(&mut self, session: AuthSession) -> Result<AuthSession, StoreError> {
        let session_id = parse_uuid(&session.id, "auth_session.id")?;
        let sql = self.update_session_sql();
        let row = self
            .tx_mut()
            .query_one(
                &sql,
                &[
                    &session_id,
                    &encode_session_status(&session.status),
                    &session
                        .device_id
                        .as_deref()
                        .map(parse_uuid_opt)
                        .transpose()?,
                    &to_epoch_secs(session.expires_at),
                    &(session.refresh_token_version as i64),
                ],
            )
            .map_err(map_write_error("update session", None))?;
        decode_session(row)
    }
}

impl DeviceStore for PostgresStoreTransaction<'_> {
    fn find_device(&mut self, device_id: &str) -> Result<Option<DeviceRecord>, StoreError> {
        let device_id = parse_uuid(device_id, "device.id")?;
        let sql = self.query_device_by_id_sql();
        let row = self
            .tx_mut()
            .query_opt(&sql, &[&device_id])
            .map_err(|error| StoreError::Backend(format!("query device by id failed: {error}")))?;
        row.map(decode_device).transpose()
    }

    fn list_devices(&mut self) -> Result<Vec<DeviceRecord>, StoreError> {
        let sql = self.list_devices_sql();
        let rows = self
            .tx_mut()
            .query(&sql, &[])
            .map_err(|error| StoreError::Backend(format!("list devices failed: {error}")))?;
        rows.into_iter().map(decode_device).collect()
    }

    fn list_devices_by_query(
        &mut self,
        query: &DeviceListQuery,
    ) -> Result<Vec<DeviceRecord>, StoreError> {
        let account_id = query
            .account_id
            .as_deref()
            .map(|value| parse_uuid(value, "account.id"))
            .transpose()?;
        let status = query.status.as_ref().map(encode_device_status);
        let registered_after = query.registered_after.map(to_epoch_secs);
        let registered_before = query.registered_before.map(to_epoch_secs);
        let cursor_time = query
            .cursor
            .as_ref()
            .map(|cursor| to_epoch_secs(cursor.sort_time));
        let cursor_id = query
            .cursor
            .as_ref()
            .map(|cursor| parse_uuid(&cursor.entity_id, "device.cursor_id"))
            .transpose()?;
        let sql = self.list_devices_by_query_sql();
        let rows = self
            .tx_mut()
            .query(
                &sql,
                &[
                    &account_id,
                    &query.client_id,
                    &status,
                    &registered_after,
                    &registered_before,
                    &cursor_time,
                    &cursor_id,
                    &query.page.fetch_limit(),
                    &query.page.sql_offset(),
                ],
            )
            .map_err(|error| {
                StoreError::Backend(format!("list devices by query failed: {error}"))
            })?;
        rows.into_iter().map(decode_device).collect()
    }

    fn count_devices_by_query(&mut self, query: &DeviceListQuery) -> Result<u64, StoreError> {
        let account_id = query
            .account_id
            .as_deref()
            .map(|value| parse_uuid(value, "account.id"))
            .transpose()?;
        let status = query.status.as_ref().map(encode_device_status);
        let registered_after = query.registered_after.map(to_epoch_secs);
        let registered_before = query.registered_before.map(to_epoch_secs);
        let sql = self.count_devices_by_query_sql();
        let count: i64 = self
            .tx_mut()
            .query_one(
                &sql,
                &[
                    &account_id,
                    &query.client_id,
                    &status,
                    &registered_after,
                    &registered_before,
                ],
            )
            .map_err(|error| {
                StoreError::Backend(format!("count devices by query failed: {error}"))
            })?
            .get(0);
        Ok(count.max(0) as u64)
    }

    fn find_device_by_proof_key_id(
        &mut self,
        proof_key_id: &str,
    ) -> Result<Option<DeviceRecord>, StoreError> {
        let sql = self.query_device_by_proof_key_id_sql();
        let row = self
            .tx_mut()
            .query_opt(&sql, &[&proof_key_id])
            .map_err(|error| {
                StoreError::Backend(format!("query device by proof key failed: {error}"))
            })?;
        row.map(decode_device).transpose()
    }

    fn insert_device(&mut self, device: DeviceRecord) -> Result<DeviceRecord, StoreError> {
        let device_id = parse_uuid(&device.id, "device.id")?;
        let sql = self.insert_device_sql();
        let row = self
            .tx_mut()
            .query_one(
                &sql,
                &[
                    &device_id,
                    &device.client_id,
                    &device.device_name,
                    &device.proof_key_id,
                    &encode_device_status(&device.status),
                    &to_epoch_secs(device.registered_at),
                    &device.last_seen_at.map(to_epoch_secs),
                ],
            )
            .map_err(map_write_error("insert device", Some("device.id")))?;
        decode_device(row)
    }

    fn update_device(&mut self, device: DeviceRecord) -> Result<DeviceRecord, StoreError> {
        let device_id = parse_uuid(&device.id, "device.id")?;
        let sql = self.update_device_sql();
        let row = self
            .tx_mut()
            .query_one(
                &sql,
                &[
                    &device_id,
                    &device.device_name,
                    &device.proof_key_id,
                    &encode_device_status(&device.status),
                    &device.last_seen_at.map(to_epoch_secs),
                ],
            )
            .map_err(map_write_error("update device", None))?;
        decode_device(row)
    }
}

impl AccountDeviceBindingStore for PostgresStoreTransaction<'_> {
    fn find_active_account_device_binding(
        &mut self,
        account_id: &str,
        device_id: &str,
    ) -> Result<Option<AccountDeviceBinding>, StoreError> {
        let account_id = parse_uuid(account_id, "account.id")?;
        let device_id = parse_uuid(device_id, "device.id")?;
        let sql = self.query_active_account_device_binding_sql();
        let row = self
            .tx_mut()
            .query_opt(&sql, &[&account_id, &device_id])
            .map_err(|error| {
                StoreError::Backend(format!(
                    "query active account device binding failed: {error}"
                ))
            })?;
        row.map(decode_account_device_binding).transpose()
    }

    fn list_account_device_bindings_by_device(
        &mut self,
        device_id: &str,
    ) -> Result<Vec<AccountDeviceBinding>, StoreError> {
        let device_id = parse_uuid(device_id, "device.id")?;
        let sql = self.list_account_device_bindings_by_device_sql();
        let rows = self.tx_mut().query(&sql, &[&device_id]).map_err(|error| {
            StoreError::Backend(format!(
                "list account device bindings by device failed: {error}"
            ))
        })?;
        rows.into_iter()
            .map(decode_account_device_binding)
            .collect()
    }

    fn list_active_account_device_bindings_by_account(
        &mut self,
        account_id: &str,
    ) -> Result<Vec<AccountDeviceBinding>, StoreError> {
        let account_id = parse_uuid(account_id, "account.id")?;
        let sql = self.list_active_account_device_bindings_by_account_sql();
        let rows = self.tx_mut().query(&sql, &[&account_id]).map_err(|error| {
            StoreError::Backend(format!(
                "list active account device bindings by account failed: {error}"
            ))
        })?;
        rows.into_iter()
            .map(decode_account_device_binding)
            .collect()
    }

    fn insert_account_device_binding(
        &mut self,
        binding: AccountDeviceBinding,
    ) -> Result<AccountDeviceBinding, StoreError> {
        let binding_id = parse_uuid(&binding.id, "account_device_binding.id")?;
        let account_id = parse_uuid(&binding.account_id, "account.id")?;
        let device_id = parse_uuid(&binding.device_id, "device.id")?;
        let sql = self.insert_account_device_binding_sql();
        let row = self
            .tx_mut()
            .query_one(
                &sql,
                &[
                    &binding_id,
                    &account_id,
                    &device_id,
                    &encode_account_device_binding_status(&binding.status),
                    &to_epoch_secs(binding.bound_at),
                    &binding.unbound_at.map(to_epoch_secs),
                    &binding.last_authenticated_at.map(to_epoch_secs),
                ],
            )
            .map_err(map_write_error(
                "insert account device binding",
                Some("account_device_binding.id"),
            ))?;
        decode_account_device_binding(row)
    }

    fn update_account_device_binding(
        &mut self,
        binding: AccountDeviceBinding,
    ) -> Result<AccountDeviceBinding, StoreError> {
        let binding_id = parse_uuid(&binding.id, "account_device_binding.id")?;
        let sql = self.update_account_device_binding_sql();
        let row = self
            .tx_mut()
            .query_one(
                &sql,
                &[
                    &binding_id,
                    &encode_account_device_binding_status(&binding.status),
                    &binding.unbound_at.map(to_epoch_secs),
                    &binding.last_authenticated_at.map(to_epoch_secs),
                ],
            )
            .map_err(map_write_error("update account device binding", None))?;
        decode_account_device_binding(row)
    }
}

impl DeviceNonceStore for PostgresStoreTransaction<'_> {
    fn find_device_nonce(
        &mut self,
        challenge: &str,
    ) -> Result<Option<DeviceNonceRecord>, StoreError> {
        let sql = self.query_device_nonce_sql();
        let row = self
            .tx_mut()
            .query_opt(&sql, &[&challenge])
            .map_err(|error| StoreError::Backend(format!("query device nonce failed: {error}")))?;
        row.map(decode_device_nonce).transpose()
    }

    fn insert_device_nonce(
        &mut self,
        nonce: DeviceNonceRecord,
    ) -> Result<DeviceNonceRecord, StoreError> {
        let nonce_id = parse_uuid(&nonce.id, "device_nonce.id")?;
        let device_id = parse_uuid(&nonce.device_id, "device.id")?;
        let sql = self.insert_device_nonce_sql();
        let row = self
            .tx_mut()
            .query_one(
                &sql,
                &[
                    &nonce_id,
                    &device_id,
                    &nonce.challenge,
                    &to_epoch_secs(nonce.issued_at),
                    &to_epoch_secs(nonce.expires_at),
                    &nonce.consumed_at.map(to_epoch_secs),
                ],
            )
            .map_err(map_write_error(
                "insert device nonce",
                Some("device_nonce.challenge"),
            ))?;
        decode_device_nonce(row)
    }

    fn consume_device_nonce(
        &mut self,
        challenge: &str,
        consumed_at: SystemTime,
    ) -> Result<Option<DeviceNonceRecord>, StoreError> {
        let sql = self.consume_device_nonce_sql();
        let row = self
            .tx_mut()
            .query_opt(&sql, &[&challenge, &to_epoch_secs(consumed_at)])
            .map_err(|error| {
                StoreError::Backend(format!("consume device nonce failed: {error}"))
            })?;
        row.map(decode_device_nonce).transpose()
    }
}

impl ClientStore for PostgresStoreTransaction<'_> {
    fn find_client(&mut self, client_id: &str) -> Result<Option<OidcClient>, StoreError> {
        let sql = self.query_client_by_id_sql();
        let row = self
            .tx_mut()
            .query_opt(&sql, &[&client_id])
            .map_err(|error| StoreError::Backend(format!("query client by id failed: {error}")))?;
        row.map(decode_client).transpose()
    }

    fn list_clients(&mut self) -> Result<Vec<OidcClient>, StoreError> {
        let sql = self.list_clients_sql();
        let rows = self
            .tx_mut()
            .query(&sql, &[])
            .map_err(|error| StoreError::Backend(format!("list clients failed: {error}")))?;
        rows.into_iter().map(decode_client).collect()
    }

    fn list_clients_by_query(
        &mut self,
        query: &ClientListQuery,
    ) -> Result<Vec<OidcClient>, StoreError> {
        let sql = self.list_clients_by_query_sql();
        let client_type = query.client_type.map(encode_client_type);
        let rows = self
            .tx_mut()
            .query(
                &sql,
                &[
                    &client_type,
                    &query.pkce_required,
                    &query.page.fetch_limit(),
                    &query.page.sql_offset(),
                ],
            )
            .map_err(|error| {
                StoreError::Backend(format!("list clients by query failed: {error}"))
            })?;
        rows.into_iter().map(decode_client).collect()
    }

    fn count_clients_by_query(&mut self, query: &ClientListQuery) -> Result<u64, StoreError> {
        let sql = self.count_clients_by_query_sql();
        let client_type = query.client_type.map(encode_client_type);
        let count: i64 = self
            .tx_mut()
            .query_one(&sql, &[&client_type, &query.pkce_required])
            .map_err(|error| {
                StoreError::Backend(format!("count clients by query failed: {error}"))
            })?
            .get(0);
        Ok(count.max(0) as u64)
    }

    fn upsert_client(&mut self, client: OidcClient) -> Result<OidcClient, StoreError> {
        let sql = self.upsert_client_sql();
        let redirect_uris_json = serde_json::to_string(&client.redirect_uris).map_err(|error| {
            StoreError::Backend(format!("encode oidc client redirect uris failed: {error}"))
        })?;
        let row = self
            .tx_mut()
            .query_one(
                &sql,
                &[
                    &client.client_id,
                    &client.client_name,
                    &redirect_uris_json,
                    &encode_client_type(client.client_type),
                    &client.pkce_required,
                    &client.client_secret_hash,
                    &to_epoch_secs(SystemTime::now()),
                ],
            )
            .map_err(map_write_error(
                "upsert oidc client",
                Some("oidc_client.id"),
            ))?;
        decode_client(row)
    }
}

impl AuthorizationCodeStore for PostgresStoreTransaction<'_> {
    fn find_authorization_code(
        &mut self,
        code: &str,
    ) -> Result<Option<AuthorizationCodeRecord>, StoreError> {
        let sql = self.query_authorization_code_sql();
        let row = self.tx_mut().query_opt(&sql, &[&code]).map_err(|error| {
            StoreError::Backend(format!("query authorization code failed: {error}"))
        })?;
        row.map(decode_authorization_code).transpose()
    }

    fn insert_authorization_code(
        &mut self,
        code: AuthorizationCodeRecord,
    ) -> Result<AuthorizationCodeRecord, StoreError> {
        let account_id = parse_uuid(&code.account_id, "account.id")?;
        let sql = self.insert_authorization_code_sql();
        let row = self
            .tx_mut()
            .query_one(
                &sql,
                &[
                    &code.code,
                    &account_id,
                    &code.client_id,
                    &code.redirect_uri,
                    &code.scope,
                    &code.nonce,
                    &code.code_challenge,
                    &code.code_challenge_method.map(encode_pkce_method),
                    &to_epoch_secs(code.created_at),
                    &to_epoch_secs(code.expires_at),
                    &code.consumed_at.map(to_epoch_secs),
                ],
            )
            .map_err(map_write_error(
                "insert authorization code",
                Some("authorization_code.code"),
            ))?;
        decode_authorization_code(row)
    }

    fn consume_authorization_code(
        &mut self,
        code: &str,
        consumed_at: SystemTime,
    ) -> Result<Option<AuthorizationCodeRecord>, StoreError> {
        let sql = self.consume_authorization_code_sql();
        let row = self
            .tx_mut()
            .query_opt(&sql, &[&code, &to_epoch_secs(consumed_at)])
            .map_err(|error| {
                StoreError::Backend(format!("consume authorization code failed: {error}"))
            })?;
        row.map(decode_authorization_code).transpose()
    }
}

impl EmailVerificationStore for PostgresStoreTransaction<'_> {
    fn find_email_verification_code(
        &mut self,
        email: &str,
        code: &str,
    ) -> Result<Option<EmailVerificationCode>, StoreError> {
        let sql = self.query_email_verification_code_sql();
        let row = self
            .tx_mut()
            .query_opt(&sql, &[&email, &code])
            .map_err(|error| {
                StoreError::Backend(format!("query email verification code failed: {error}"))
            })?;
        row.map(decode_email_verification_code).transpose()
    }

    fn insert_email_verification_code(
        &mut self,
        verification: EmailVerificationCode,
    ) -> Result<EmailVerificationCode, StoreError> {
        let verification_id = parse_uuid(&verification.id, "email_verification.id")?;
        let account_id = parse_uuid(&verification.account_id, "account.id")?;
        let sql = self.insert_email_verification_code_sql();
        let row = self
            .tx_mut()
            .query_one(
                &sql,
                &[
                    &verification_id,
                    &account_id,
                    &verification.email,
                    &verification.code,
                    &to_epoch_secs(verification.issued_at),
                    &to_epoch_secs(verification.expires_at),
                    &verification.consumed_at.map(to_epoch_secs),
                ],
            )
            .map_err(map_write_error(
                "insert email verification code",
                Some("email_verification.code"),
            ))?;
        decode_email_verification_code(row)
    }

    fn consume_email_verification_code(
        &mut self,
        verification_id: &str,
        consumed_at: SystemTime,
    ) -> Result<Option<EmailVerificationCode>, StoreError> {
        let verification_id = parse_uuid(verification_id, "email_verification.id")?;
        let sql = self.consume_email_verification_code_sql();
        let row = self
            .tx_mut()
            .query_opt(&sql, &[&verification_id, &to_epoch_secs(consumed_at)])
            .map_err(|error| {
                StoreError::Backend(format!("consume email verification code failed: {error}"))
            })?;
        row.map(decode_email_verification_code).transpose()
    }

    fn consume_email_verification_codes_for_account(
        &mut self,
        account_id: &str,
        consumed_at: SystemTime,
    ) -> Result<Vec<EmailVerificationCode>, StoreError> {
        let account_id = parse_uuid(account_id, "account.id")?;
        let sql = self.consume_email_verification_codes_for_account_sql();
        let rows = self
            .tx_mut()
            .query(&sql, &[&account_id, &to_epoch_secs(consumed_at)])
            .map_err(|error| {
                StoreError::Backend(format!(
                    "consume account email verification codes failed: {error}"
                ))
            })?;
        rows.into_iter()
            .map(decode_email_verification_code)
            .collect()
    }
}

impl RefreshTokenStore for PostgresStoreTransaction<'_> {
    fn find_refresh_token(
        &mut self,
        token_digest: &[u8; 32],
    ) -> Result<Option<RefreshTokenRecord>, StoreError> {
        let sql = self.query_refresh_token_sql();
        let row = self
            .tx_mut()
            .query_opt(&sql, &[&token_digest.as_slice()])
            .map_err(|error| StoreError::Backend(format!("query refresh token failed: {error}")))?;
        row.map(decode_refresh_token).transpose()
    }

    fn insert_refresh_token(
        &mut self,
        token: RefreshTokenRecord,
    ) -> Result<RefreshTokenRecord, StoreError> {
        let refresh_token_id = parse_uuid(&token.id, "refresh_token.id")?;
        let session_id = parse_uuid(&token.session_id, "auth_session.id")?;
        let sql = self.insert_refresh_token_sql();
        let row = self
            .tx_mut()
            .query_one(
                &sql,
                &[
                    &refresh_token_id,
                    &session_id,
                    &token.token_digest.as_slice(),
                    &(token.token_version as i64),
                    &to_epoch_secs(token.issued_at),
                    &to_epoch_secs(token.expires_at),
                    &token.revoked_at.map(to_epoch_secs),
                    &token
                        .revocation_reason
                        .map(encode_refresh_revocation_reason),
                ],
            )
            .map_err(map_write_error(
                "insert refresh token",
                Some("refresh_token.digest"),
            ))?;
        decode_refresh_token(row)
    }

    fn revoke_refresh_token(
        &mut self,
        token_digest: &[u8; 32],
        reason: RefreshTokenRevocationReason,
        revoked_at: SystemTime,
    ) -> Result<Option<RefreshTokenRecord>, StoreError> {
        let sql = self.revoke_refresh_token_sql();
        let row = self
            .tx_mut()
            .query_opt(
                &sql,
                &[
                    &token_digest.as_slice(),
                    &encode_refresh_revocation_reason(reason),
                    &to_epoch_secs(revoked_at),
                ],
            )
            .map_err(|error| {
                StoreError::Backend(format!("revoke refresh token failed: {error}"))
            })?;
        row.map(decode_refresh_token).transpose()
    }

    fn revoke_refresh_tokens_for_session(
        &mut self,
        session_id: &str,
        reason: RefreshTokenRevocationReason,
        revoked_at: SystemTime,
    ) -> Result<Vec<RefreshTokenRecord>, StoreError> {
        let session_id = parse_uuid(session_id, "auth_session.id")?;
        let sql = self.revoke_refresh_tokens_for_session_sql();
        let rows = self
            .tx_mut()
            .query(
                &sql,
                &[
                    &session_id,
                    &encode_refresh_revocation_reason(reason),
                    &to_epoch_secs(revoked_at),
                ],
            )
            .map_err(|error| {
                StoreError::Backend(format!("revoke session refresh tokens failed: {error}"))
            })?;
        rows.into_iter().map(decode_refresh_token).collect()
    }
}

impl ProofBoundRefreshTransaction for PostgresStoreTransaction<'_> {
    fn lock_refresh_token(
        &mut self,
        digest: &[u8; 32],
    ) -> Result<Option<RefreshTokenRecord>, StoreError> {
        RefreshTokenStore::find_refresh_token(self, digest)
    }

    fn lock_session(&mut self, session_id: &str) -> Result<Option<AuthSession>, StoreError> {
        let session_id = parse_uuid(session_id, "auth_session.id")?;
        let sql = format!(
            "select id, account_id, client_id, device_id, status, created_at_epoch, expires_at_epoch, refresh_token_version \
             from {}.auth_sessions where id = $1::uuid limit 1 for update",
            self.schema_name
        );
        let row = self
            .tx_mut()
            .query_opt(&sql, &[&session_id])
            .map_err(|error| StoreError::Backend(format!("lock auth session failed: {error}")))?;
        row.map(decode_session).transpose()
    }

    fn lock_account(&mut self, account_id: &str) -> Result<Option<Account>, StoreError> {
        let account_id = parse_uuid(account_id, "account.id")?;
        let sql = format!(
            "select id, email, password_hash, display_name, status, created_at_epoch \
             from {}.accounts where id = $1::uuid limit 1 for update",
            self.schema_name
        );
        let row = self
            .tx_mut()
            .query_opt(&sql, &[&account_id])
            .map_err(|error| StoreError::Backend(format!("lock account failed: {error}")))?;
        row.map(decode_account).transpose()
    }

    fn lock_device(&mut self, device_id: &str) -> Result<Option<DeviceRecord>, StoreError> {
        let device_id = parse_uuid(device_id, "device.id")?;
        let sql = format!(
            "select id, client_id, device_name, proof_key_id, status, registered_at_epoch, last_seen_at_epoch \
             from {}.devices where id = $1::uuid limit 1 for update",
            self.schema_name
        );
        let row = self
            .tx_mut()
            .query_opt(&sql, &[&device_id])
            .map_err(|error| StoreError::Backend(format!("lock device failed: {error}")))?;
        row.map(decode_device).transpose()
    }

    fn lock_device_key(
        &mut self,
        key_id: &str,
    ) -> Result<Option<DeviceProofKeyRecord>, StoreError> {
        let sql = format!(
            "select key_id, device_id, algorithm, public_jwk, version, status, registered_at_epoch, retired_at_epoch \
             from {}.device_proof_keys where key_id = $1 limit 1 for update",
            self.schema_name
        );
        let row = self.tx_mut().query_opt(&sql, &[&key_id]).map_err(|error| {
            StoreError::Backend(format!("lock device proof key failed: {error}"))
        })?;
        row.map(decode_device_proof_key).transpose()
    }

    fn lock_active_binding(
        &mut self,
        account_id: &str,
        device_id: &str,
    ) -> Result<Option<AccountDeviceBinding>, StoreError> {
        let account_id = parse_uuid(account_id, "account.id")?;
        let device_id = parse_uuid(device_id, "device.id")?;
        let sql = format!(
            "select id, account_id, device_id, status, bound_at_epoch, unbound_at_epoch, last_authenticated_at_epoch \
             from {}.account_device_bindings \
             where account_id = $1::uuid and device_id = $2::uuid and status = 'active' \
             limit 1 for update",
            self.schema_name
        );
        let row = self
            .tx_mut()
            .query_opt(&sql, &[&account_id, &device_id])
            .map_err(|error| {
                StoreError::Backend(format!("lock account device binding failed: {error}"))
            })?;
        row.map(decode_account_device_binding).transpose()
    }

    fn lock_challenge(
        &mut self,
        digest: &[u8; 32],
    ) -> Result<Option<DeviceProofChallengeRecord>, StoreError> {
        let sql = format!(
            "select id, device_id, purpose, challenge_digest, issued_at_epoch, expires_at_epoch, consumed_at_epoch \
             from {}.device_nonces where challenge_digest = $1 limit 1 for update",
            self.schema_name
        );
        let row = self
            .tx_mut()
            .query_opt(&sql, &[&digest.as_slice()])
            .map_err(|error| {
                StoreError::Backend(format!("lock device proof challenge failed: {error}"))
            })?;
        row.map(decode_device_proof_challenge).transpose()
    }

    fn consume_challenge_if_active(
        &mut self,
        digest: &[u8; 32],
        observed_at: SystemTime,
    ) -> Result<bool, StoreError> {
        let sql = format!(
            "update {}.device_nonces set consumed_at_epoch = $2 \
             where challenge_digest = $1 and consumed_at_epoch is null and expires_at_epoch > $2",
            self.schema_name
        );
        let updated = self
            .tx_mut()
            .execute(&sql, &[&digest.as_slice(), &to_epoch_secs(observed_at)])
            .map_err(|error| {
                StoreError::Backend(format!("consume device proof challenge failed: {error}"))
            })?;
        Ok(updated == 1)
    }

    fn update_session(&mut self, session: AuthSession) -> Result<AuthSession, StoreError> {
        SessionStore::update_session(self, session)
    }

    fn revoke_refresh_token(
        &mut self,
        digest: &[u8; 32],
        reason: RefreshTokenRevocationReason,
        revoked_at: SystemTime,
    ) -> Result<(), StoreError> {
        RefreshTokenStore::revoke_refresh_token(self, digest, reason, revoked_at)?
            .ok_or(StoreError::NotFound("refresh_token.digest"))?;
        Ok(())
    }

    fn insert_refresh_token(&mut self, token: RefreshTokenRecord) -> Result<(), StoreError> {
        RefreshTokenStore::insert_refresh_token(self, token)?;
        Ok(())
    }

    fn revoke_refresh_family(
        &mut self,
        session_id: &str,
        reason: RefreshTokenRevocationReason,
        revoked_at: SystemTime,
    ) -> Result<(), StoreError> {
        RefreshTokenStore::revoke_refresh_tokens_for_session(self, session_id, reason, revoked_at)?;
        Ok(())
    }
}

impl DeviceRequestVerificationTransaction for PostgresStoreTransaction<'_> {
    fn lock_device(&mut self, device_id: &str) -> Result<Option<DeviceRecord>, StoreError> {
        ProofBoundRefreshTransaction::lock_device(self, device_id)
    }

    fn lock_device_key(
        &mut self,
        key_id: &str,
    ) -> Result<Option<DeviceProofKeyRecord>, StoreError> {
        ProofBoundRefreshTransaction::lock_device_key(self, key_id)
    }

    fn lock_active_binding(
        &mut self,
        account_id: &str,
        device_id: &str,
    ) -> Result<Option<AccountDeviceBinding>, StoreError> {
        ProofBoundRefreshTransaction::lock_active_binding(self, account_id, device_id)
    }

    fn lock_challenge(
        &mut self,
        digest: &[u8; 32],
    ) -> Result<Option<DeviceProofChallengeRecord>, StoreError> {
        ProofBoundRefreshTransaction::lock_challenge(self, digest)
    }

    fn consume_challenge_if_active(
        &mut self,
        digest: &[u8; 32],
        observed_at: SystemTime,
    ) -> Result<bool, StoreError> {
        ProofBoundRefreshTransaction::consume_challenge_if_active(self, digest, observed_at)
    }
}

impl DeviceSecurityTransaction for PostgresStoreTransaction<'_> {
    fn find_client(&mut self, client_id: &str) -> Result<Option<OidcClient>, StoreError> {
        ClientStore::find_client(self, client_id)
    }

    fn insert_device(&mut self, device: DeviceRecord) -> Result<DeviceRecord, StoreError> {
        DeviceStore::insert_device(self, device)
    }

    fn find_device_for_challenge(
        &mut self,
        device_id: &str,
    ) -> Result<Option<DeviceRecord>, StoreError> {
        let Ok(device_id) = Uuid::parse_str(device_id) else {
            return Ok(None);
        };
        let sql = format!(
            "select id, client_id, device_name, proof_key_id, status, registered_at_epoch, last_seen_at_epoch \
             from {}.devices where id = $1::uuid limit 1 for update",
            self.schema_name
        );
        let row = self
            .tx_mut()
            .query_opt(&sql, &[&device_id])
            .map_err(|error| {
                StoreError::Backend(format!("lock challenge device failed: {error}"))
            })?;
        row.map(decode_device).transpose()
    }

    fn lock_device(&mut self, device_id: &str) -> Result<Option<DeviceRecord>, StoreError> {
        ProofBoundRefreshTransaction::lock_device(self, device_id)
    }

    fn update_device(&mut self, device: DeviceRecord) -> Result<DeviceRecord, StoreError> {
        DeviceStore::update_device(self, device)
    }

    fn lock_active_device_key(
        &mut self,
        device_id: &str,
    ) -> Result<Option<DeviceProofKeyRecord>, StoreError> {
        let device_id = parse_uuid(device_id, "device.id")?;
        let sql = format!(
            "select key_id, device_id, algorithm, public_jwk, version, status, registered_at_epoch, retired_at_epoch \
             from {}.device_proof_keys where device_id = $1::uuid and status = 'active' \
             limit 1 for update",
            self.schema_name
        );
        let row = self
            .tx_mut()
            .query_opt(&sql, &[&device_id])
            .map_err(|error| {
                StoreError::Backend(format!("lock active device proof key failed: {error}"))
            })?;
        row.map(decode_device_proof_key).transpose()
    }

    fn lock_device_key(
        &mut self,
        key_id: &str,
    ) -> Result<Option<DeviceProofKeyRecord>, StoreError> {
        ProofBoundRefreshTransaction::lock_device_key(self, key_id)
    }

    fn insert_device_key(
        &mut self,
        key: DeviceProofKeyRecord,
    ) -> Result<DeviceProofKeyRecord, StoreError> {
        key.validate()
            .map_err(|error| StoreError::Backend(format!("invalid device proof key: {error:?}")))?;
        let device_id = parse_uuid(&key.device_id, "device.id")?;
        let status = encode_device_proof_key_status(key.status);
        let sql = format!(
            "insert into {}.device_proof_keys \
             (key_id, device_id, algorithm, public_jwk, version, status, registered_at_epoch, retired_at_epoch) \
             values ($1, $2::uuid, 'ed25519', $3, $4, $5, $6, $7) \
             returning key_id, device_id, algorithm, public_jwk, version, status, registered_at_epoch, retired_at_epoch",
            self.schema_name
        );
        let row = self
            .tx_mut()
            .query_one(
                &sql,
                &[
                    &key.key_id,
                    &device_id,
                    &key.public_jwk,
                    &(key.version as i64),
                    &status,
                    &to_epoch_secs(key.registered_at),
                    &key.retired_at.map(to_epoch_secs),
                ],
            )
            .map_err(map_write_error(
                "insert device proof key",
                Some("device_proof_key.id"),
            ))?;
        decode_device_proof_key(row)
    }

    fn update_device_key(
        &mut self,
        key: DeviceProofKeyRecord,
    ) -> Result<DeviceProofKeyRecord, StoreError> {
        key.validate()
            .map_err(|error| StoreError::Backend(format!("invalid device proof key: {error:?}")))?;
        let status = encode_device_proof_key_status(key.status);
        let sql = format!(
            "update {}.device_proof_keys set status = $2, retired_at_epoch = $3 \
             where key_id = $1 \
             returning key_id, device_id, algorithm, public_jwk, version, status, registered_at_epoch, retired_at_epoch",
            self.schema_name
        );
        let row = self
            .tx_mut()
            .query_opt(
                &sql,
                &[&key.key_id, &status, &key.retired_at.map(to_epoch_secs)],
            )
            .map_err(|error| {
                StoreError::Backend(format!("update device proof key failed: {error}"))
            })?
            .ok_or(StoreError::NotFound("device_proof_key.id"))?;
        decode_device_proof_key(row)
    }

    fn lock_active_binding(
        &mut self,
        account_id: &str,
        device_id: &str,
    ) -> Result<Option<AccountDeviceBinding>, StoreError> {
        ProofBoundRefreshTransaction::lock_active_binding(self, account_id, device_id)
    }

    fn insert_challenge(
        &mut self,
        challenge: DeviceProofChallengeRecord,
    ) -> Result<DeviceProofChallengeRecord, StoreError> {
        let challenge_id = parse_uuid(&challenge.id, "device_challenge.id")?;
        let device_id = parse_uuid(&challenge.device_id, "device.id")?;
        let sql = format!(
            "insert into {}.device_nonces \
             (id, device_id, challenge, purpose, challenge_digest, issued_at_epoch, expires_at_epoch, consumed_at_epoch) \
             values ($1::uuid, $2::uuid, null, $3, $4, $5, $6, $7) \
             returning id, device_id, purpose, challenge_digest, issued_at_epoch, expires_at_epoch, consumed_at_epoch",
            self.schema_name
        );
        let row = self
            .tx_mut()
            .query_one(
                &sql,
                &[
                    &challenge_id,
                    &device_id,
                    &challenge.purpose.as_str(),
                    &challenge.challenge_digest.as_slice(),
                    &to_epoch_secs(challenge.issued_at),
                    &to_epoch_secs(challenge.expires_at),
                    &challenge.consumed_at.map(to_epoch_secs),
                ],
            )
            .map_err(map_write_error(
                "insert device proof challenge",
                Some("device_challenge.digest"),
            ))?;
        decode_device_proof_challenge(row)
    }

    fn lock_challenge(
        &mut self,
        digest: &[u8; 32],
    ) -> Result<Option<DeviceProofChallengeRecord>, StoreError> {
        ProofBoundRefreshTransaction::lock_challenge(self, digest)
    }

    fn consume_challenge_if_active(
        &mut self,
        digest: &[u8; 32],
        observed_at: SystemTime,
    ) -> Result<bool, StoreError> {
        ProofBoundRefreshTransaction::consume_challenge_if_active(self, digest, observed_at)
    }
}

fn encode_device_proof_key_status(status: DeviceProofKeyStatus) -> &'static str {
    match status {
        DeviceProofKeyStatus::Active => "active",
        DeviceProofKeyStatus::Retired => "retired",
    }
}

fn map_write_error(
    operation: &'static str,
    conflict_key: Option<&'static str>,
) -> impl FnOnce(postgres::Error) -> StoreError {
    move |error| {
        if let Some(db_error) = error.as_db_error() {
            if db_error.code().code() == "23505" {
                return StoreError::Conflict(conflict_key.unwrap_or(operation));
            }
        }
        StoreError::Backend(format!("{operation} failed: {error}"))
    }
}

fn decode_account(row: Row) -> Result<Account, StoreError> {
    Ok(Account {
        id: decode_uuid(&row, "id"),
        email: row.get("email"),
        password_hash: row.get("password_hash"),
        display_name: row.get("display_name"),
        status: decode_account_status(row.get("status"))?,
        created_at: from_epoch_secs(row.get("created_at_epoch")),
    })
}

fn decode_session(row: Row) -> Result<AuthSession, StoreError> {
    Ok(AuthSession {
        id: decode_uuid(&row, "id"),
        account_id: decode_uuid(&row, "account_id"),
        client_id: row.get("client_id"),
        device_id: row
            .get::<_, Option<Uuid>>("device_id")
            .map(|value| value.to_string()),
        status: decode_session_status(row.get("status"))?,
        created_at: from_epoch_secs(row.get("created_at_epoch")),
        expires_at: from_epoch_secs(row.get("expires_at_epoch")),
        refresh_token_version: row.get::<_, i64>("refresh_token_version") as u64,
    })
}

fn decode_email_verification_code(row: Row) -> Result<EmailVerificationCode, StoreError> {
    Ok(EmailVerificationCode {
        id: decode_uuid(&row, "id"),
        account_id: decode_uuid(&row, "account_id"),
        email: row.get("email"),
        code: row.get("code"),
        issued_at: from_epoch_secs(row.get("issued_at_epoch")),
        expires_at: from_epoch_secs(row.get("expires_at_epoch")),
        consumed_at: row
            .get::<_, Option<i64>>("consumed_at_epoch")
            .map(from_epoch_secs),
    })
}

fn decode_device(row: Row) -> Result<DeviceRecord, StoreError> {
    Ok(DeviceRecord {
        id: decode_uuid(&row, "id"),
        client_id: row.get("client_id"),
        device_name: row.get("device_name"),
        proof_key_id: row.get("proof_key_id"),
        status: decode_device_status(row.get("status"))?,
        registered_at: from_epoch_secs(row.get("registered_at_epoch")),
        last_seen_at: row
            .get::<_, Option<i64>>("last_seen_at_epoch")
            .map(from_epoch_secs),
    })
}

fn decode_device_proof_key(row: Row) -> Result<DeviceProofKeyRecord, StoreError> {
    let algorithm: String = row.get("algorithm");
    if algorithm != "ed25519" {
        return Err(StoreError::Backend(format!(
            "unknown device proof algorithm: {algorithm}"
        )));
    }
    let status = match row.get::<_, String>("status").as_str() {
        "active" => DeviceProofKeyStatus::Active,
        "retired" => DeviceProofKeyStatus::Retired,
        value => {
            return Err(StoreError::Backend(format!(
                "unknown device proof key status: {value}"
            )))
        }
    };
    Ok(DeviceProofKeyRecord {
        key_id: row.get("key_id"),
        device_id: decode_uuid(&row, "device_id"),
        algorithm: DeviceProofAlgorithm::Ed25519,
        public_jwk: row.get("public_jwk"),
        version: row.get::<_, i64>("version") as u64,
        status,
        registered_at: from_epoch_secs(row.get("registered_at_epoch")),
        retired_at: row
            .get::<_, Option<i64>>("retired_at_epoch")
            .map(from_epoch_secs),
    })
}

fn decode_device_proof_challenge(row: Row) -> Result<DeviceProofChallengeRecord, StoreError> {
    let digest: Vec<u8> = row.get("challenge_digest");
    let challenge_digest: [u8; 32] = digest.try_into().map_err(|_| {
        StoreError::Backend("device challenge digest must contain exactly 32 bytes".to_string())
    })?;
    let purpose = DeviceProofPurpose::new(row.get::<_, String>("purpose"))
        .map_err(|error| StoreError::Backend(format!("invalid device proof purpose: {error:?}")))?;
    Ok(DeviceProofChallengeRecord {
        id: decode_uuid(&row, "id"),
        device_id: decode_uuid(&row, "device_id"),
        purpose,
        challenge_digest,
        issued_at: from_epoch_secs(row.get("issued_at_epoch")),
        expires_at: from_epoch_secs(row.get("expires_at_epoch")),
        consumed_at: row
            .get::<_, Option<i64>>("consumed_at_epoch")
            .map(from_epoch_secs),
    })
}

fn decode_account_device_binding(row: Row) -> Result<AccountDeviceBinding, StoreError> {
    Ok(AccountDeviceBinding {
        id: decode_uuid(&row, "id"),
        account_id: decode_uuid(&row, "account_id"),
        device_id: decode_uuid(&row, "device_id"),
        status: decode_account_device_binding_status(row.get("status"))?,
        bound_at: from_epoch_secs(row.get("bound_at_epoch")),
        unbound_at: row
            .get::<_, Option<i64>>("unbound_at_epoch")
            .map(from_epoch_secs),
        last_authenticated_at: row
            .get::<_, Option<i64>>("last_authenticated_at_epoch")
            .map(from_epoch_secs),
    })
}

fn decode_device_nonce(row: Row) -> Result<DeviceNonceRecord, StoreError> {
    Ok(DeviceNonceRecord {
        id: decode_uuid(&row, "id"),
        device_id: decode_uuid(&row, "device_id"),
        challenge: row.get("challenge"),
        issued_at: from_epoch_secs(row.get("issued_at_epoch")),
        expires_at: from_epoch_secs(row.get("expires_at_epoch")),
        consumed_at: row
            .get::<_, Option<i64>>("consumed_at_epoch")
            .map(from_epoch_secs),
    })
}

fn decode_client(row: Row) -> Result<OidcClient, StoreError> {
    let redirect_uris_json: String = row.get("redirect_uris_json");
    let redirect_uris =
        serde_json::from_str::<Vec<String>>(&redirect_uris_json).map_err(|error| {
            StoreError::Backend(format!("decode oidc client redirect uris failed: {error}"))
        })?;

    Ok(OidcClient {
        client_id: row.get("client_id"),
        client_name: row.get("client_name"),
        redirect_uris,
        client_type: decode_client_type(row.get("client_type"))?,
        pkce_required: row.get("pkce_required"),
        client_secret_hash: row.get("client_secret_hash"),
    })
}

fn encode_client_type(value: OidcClientType) -> &'static str {
    match value {
        OidcClientType::PublicDesktop => "public_desktop",
        OidcClientType::ConfidentialWeb => "confidential_web",
    }
}

fn decode_authorization_code(row: Row) -> Result<AuthorizationCodeRecord, StoreError> {
    Ok(AuthorizationCodeRecord {
        code: row.get("code"),
        account_id: decode_uuid(&row, "account_id"),
        client_id: row.get("client_id"),
        redirect_uri: row.get("redirect_uri"),
        scope: row.get("scope"),
        nonce: row.get("nonce"),
        code_challenge: row.get("code_challenge"),
        code_challenge_method: row
            .get::<_, Option<String>>("code_challenge_method")
            .map(decode_pkce_method)
            .transpose()?,
        created_at: from_epoch_secs(row.get("created_at_epoch")),
        expires_at: from_epoch_secs(row.get("expires_at_epoch")),
        consumed_at: row
            .get::<_, Option<i64>>("consumed_at_epoch")
            .map(from_epoch_secs),
    })
}

fn decode_refresh_token(row: Row) -> Result<RefreshTokenRecord, StoreError> {
    let digest: Vec<u8> = row.get("token_digest");
    let token_digest: [u8; 32] = digest.try_into().map_err(|_| {
        StoreError::Backend("refresh token digest must contain exactly 32 bytes".to_string())
    })?;
    Ok(RefreshTokenRecord {
        id: decode_uuid(&row, "id"),
        session_id: decode_uuid(&row, "session_id"),
        token_digest,
        token_version: row.get::<_, i64>("token_version") as u64,
        issued_at: from_epoch_secs(row.get("issued_at_epoch")),
        expires_at: from_epoch_secs(row.get("expires_at_epoch")),
        revoked_at: row
            .get::<_, Option<i64>>("revoked_at_epoch")
            .map(from_epoch_secs),
        revocation_reason: row
            .get::<_, Option<String>>("revocation_reason")
            .map(decode_refresh_revocation_reason)
            .transpose()?,
    })
}

fn decode_uuid(row: &Row, column: &'static str) -> String {
    row.get::<_, Uuid>(column).to_string()
}

fn parse_uuid(value: &str, field: &'static str) -> Result<Uuid, StoreError> {
    Uuid::parse_str(value)
        .map_err(|error| StoreError::Backend(format!("invalid uuid for {field}: {error}")))
}

fn parse_uuid_opt(value: &str) -> Result<Uuid, StoreError> {
    Uuid::parse_str(value)
        .map_err(|error| StoreError::Backend(format!("invalid uuid value: {error}")))
}

fn encode_account_status(status: &AccountStatus) -> &'static str {
    match status {
        AccountStatus::PendingVerification => "pending_verification",
        AccountStatus::Active => "active",
        AccountStatus::Disabled => "disabled",
    }
}

fn decode_account_status(value: String) -> Result<AccountStatus, StoreError> {
    match value.as_str() {
        "pending_verification" => Ok(AccountStatus::PendingVerification),
        "active" => Ok(AccountStatus::Active),
        "disabled" => Ok(AccountStatus::Disabled),
        _ => Err(StoreError::Backend(format!(
            "unknown account status: {value}"
        ))),
    }
}

fn encode_session_status(status: &SessionStatus) -> &'static str {
    match status {
        SessionStatus::Pending => "pending",
        SessionStatus::Active => "active",
        SessionStatus::Revoked => "revoked",
        SessionStatus::Expired => "expired",
    }
}

fn decode_session_status(value: String) -> Result<SessionStatus, StoreError> {
    match value.as_str() {
        "pending" => Ok(SessionStatus::Pending),
        "active" => Ok(SessionStatus::Active),
        "revoked" => Ok(SessionStatus::Revoked),
        "expired" => Ok(SessionStatus::Expired),
        _ => Err(StoreError::Backend(format!(
            "unknown session status: {value}"
        ))),
    }
}

fn encode_device_status(status: &DeviceStatus) -> &'static str {
    match status {
        DeviceStatus::Pending => "pending",
        DeviceStatus::Active => "active",
        DeviceStatus::Disabled => "disabled",
        DeviceStatus::Revoked => "revoked",
    }
}

fn decode_device_status(value: String) -> Result<DeviceStatus, StoreError> {
    match value.as_str() {
        "pending" => Ok(DeviceStatus::Pending),
        "active" => Ok(DeviceStatus::Active),
        "disabled" => Ok(DeviceStatus::Disabled),
        "revoked" => Ok(DeviceStatus::Revoked),
        _ => Err(StoreError::Backend(format!(
            "unknown device status: {value}"
        ))),
    }
}

fn encode_account_device_binding_status(status: &AccountDeviceBindingStatus) -> &'static str {
    match status {
        AccountDeviceBindingStatus::Active => "active",
        AccountDeviceBindingStatus::Unbound => "unbound",
        AccountDeviceBindingStatus::Suspended => "suspended",
    }
}

fn decode_account_device_binding_status(
    value: String,
) -> Result<AccountDeviceBindingStatus, StoreError> {
    match value.as_str() {
        "active" => Ok(AccountDeviceBindingStatus::Active),
        "unbound" => Ok(AccountDeviceBindingStatus::Unbound),
        "suspended" => Ok(AccountDeviceBindingStatus::Suspended),
        _ => Err(StoreError::Backend(format!(
            "unknown account device binding status: {value}"
        ))),
    }
}

fn encode_refresh_revocation_reason(reason: RefreshTokenRevocationReason) -> &'static str {
    match reason {
        RefreshTokenRevocationReason::Rotated => "rotated",
        RefreshTokenRevocationReason::ReuseDetected => "reuse_detected",
        RefreshTokenRevocationReason::Logout => "logout",
        RefreshTokenRevocationReason::ClientRevocation => "client_revocation",
        RefreshTokenRevocationReason::Administrative => "administrative",
        RefreshTokenRevocationReason::SecurityCutover => "security_cutover",
    }
}

fn decode_refresh_revocation_reason(
    value: String,
) -> Result<RefreshTokenRevocationReason, StoreError> {
    match value.as_str() {
        "rotated" => Ok(RefreshTokenRevocationReason::Rotated),
        "reuse_detected" => Ok(RefreshTokenRevocationReason::ReuseDetected),
        "logout" => Ok(RefreshTokenRevocationReason::Logout),
        "client_revocation" => Ok(RefreshTokenRevocationReason::ClientRevocation),
        "administrative" => Ok(RefreshTokenRevocationReason::Administrative),
        "security_cutover" => Ok(RefreshTokenRevocationReason::SecurityCutover),
        _ => Err(StoreError::Backend(format!(
            "unknown refresh token revocation reason: {value}"
        ))),
    }
}

fn decode_client_type(value: String) -> Result<OidcClientType, StoreError> {
    match value.as_str() {
        "public_desktop" => Ok(OidcClientType::PublicDesktop),
        "confidential_web" => Ok(OidcClientType::ConfidentialWeb),
        _ => Err(StoreError::Backend(format!("unknown client type: {value}"))),
    }
}

fn encode_pkce_method(value: PkceChallengeMethod) -> &'static str {
    match value {
        PkceChallengeMethod::Plain => "plain",
        PkceChallengeMethod::S256 => "S256",
    }
}

fn decode_pkce_method(value: String) -> Result<PkceChallengeMethod, StoreError> {
    match value.as_str() {
        "plain" => Ok(PkceChallengeMethod::Plain),
        "S256" => Ok(PkceChallengeMethod::S256),
        _ => Err(StoreError::Backend(format!(
            "unknown pkce challenge method: {value}"
        ))),
    }
}

fn to_epoch_secs(value: SystemTime) -> i64 {
    value
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs() as i64
}

fn from_epoch_secs(value: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(value as u64)
}

#[cfg(test)]
mod tests {
    use super::{
        decode_account_device_binding_status, decode_account_status, decode_client_type,
        decode_device_status, decode_pkce_method, decode_session_status,
        encode_account_device_binding_status, encode_account_status, encode_device_status,
        encode_pkce_method, encode_session_status,
    };
    use embedded_idp_core::{
        AccountDeviceBindingStatus, AccountStatus, DeviceStatus, OidcClientType,
        PkceChallengeMethod, SessionStatus, StoreError,
    };

    #[test]
    fn status_codecs_round_trip_known_values() {
        assert_eq!(encode_account_status(&AccountStatus::Active), "active");
        assert_eq!(encode_session_status(&SessionStatus::Revoked), "revoked");
        assert_eq!(encode_device_status(&DeviceStatus::Pending), "pending");
        assert_eq!(encode_device_status(&DeviceStatus::Disabled), "disabled");
        assert_eq!(
            encode_account_device_binding_status(&AccountDeviceBindingStatus::Suspended),
            "suspended"
        );
        assert_eq!(encode_pkce_method(PkceChallengeMethod::S256), "S256");
        assert_eq!(
            decode_account_status("disabled".to_string()),
            Ok(AccountStatus::Disabled)
        );
        assert_eq!(
            decode_session_status("active".to_string()),
            Ok(SessionStatus::Active)
        );
        assert_eq!(
            decode_device_status("pending".to_string()),
            Ok(DeviceStatus::Pending)
        );
        assert_eq!(
            decode_device_status("revoked".to_string()),
            Ok(DeviceStatus::Revoked)
        );
        assert_eq!(
            decode_account_device_binding_status("unbound".to_string()),
            Ok(AccountDeviceBindingStatus::Unbound)
        );
        assert_eq!(
            decode_client_type("public_desktop".to_string()),
            Ok(OidcClientType::PublicDesktop)
        );
        assert_eq!(
            decode_pkce_method("plain".to_string()),
            Ok(PkceChallengeMethod::Plain)
        );
    }

    #[test]
    fn status_codecs_reject_unknown_values() {
        assert_eq!(
            decode_account_status("mystery".to_string()),
            Err(StoreError::Backend(
                "unknown account status: mystery".to_string()
            ))
        );
        assert_eq!(
            decode_session_status("mystery".to_string()),
            Err(StoreError::Backend(
                "unknown session status: mystery".to_string()
            ))
        );
        assert_eq!(
            decode_device_status("mystery".to_string()),
            Err(StoreError::Backend(
                "unknown device status: mystery".to_string()
            ))
        );
        assert_eq!(
            decode_account_device_binding_status("mystery".to_string()),
            Err(StoreError::Backend(
                "unknown account device binding status: mystery".to_string()
            ))
        );
        assert_eq!(
            decode_client_type("mystery".to_string()),
            Err(StoreError::Backend(
                "unknown client type: mystery".to_string()
            ))
        );
        assert_eq!(
            decode_pkce_method("mystery".to_string()),
            Err(StoreError::Backend(
                "unknown pkce challenge method: mystery".to_string()
            ))
        );
    }
}
