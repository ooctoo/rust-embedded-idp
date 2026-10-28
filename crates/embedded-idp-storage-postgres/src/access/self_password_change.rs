use super::{
    access_db_error, epoch,
    self_sessions::{lock_self_actor, self_actor_is_active},
    time, PostgresAccessStore,
};
use crate::{security_runtime::check_runtime_in_transaction, PgTransaction};
use embedded_idp_core::{access::*, SecretString, SecurityDigest, StoreError};
use std::time::SystemTime;
use tokio_postgres::IsolationLevel;
use uuid::Uuid;

pub struct PostgresSelfPasswordChangeReadTransaction<'a> {
    tx: PgTransaction<'a>,
    schema: &'a str,
}
pub struct PostgresSelfPasswordChangeWriteTransaction<'a> {
    read: PostgresSelfPasswordChangeReadTransaction<'a>,
}

impl SelfPasswordChangeStore for PostgresAccessStore {
    type ReadTransaction<'a> = PostgresSelfPasswordChangeReadTransaction<'a>;
    type WriteTransaction<'a> = PostgresSelfPasswordChangeWriteTransaction<'a>;

    fn password_change_read<R>(
        &self,
        mode: TenancyMode,
        authority: &str,
        actor: Option<&AccessActor>,
        run: impl FnOnce(&mut Self::ReadTransaction<'_>) -> Result<R, AccessError>,
    ) -> Result<R, AccessError> {
        if mode != self.mode {
            return Err(AccessError::ModeMismatch);
        }
        let mut client = self.adapter.connect()?;
        let mut tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .map_err(access_db_error)?;
        tx.batch_execute("set local statement_timeout='5s'; set local lock_timeout='5s'")
            .map_err(access_db_error)?;
        let schema = self.adapter.schema_name();
        tx.query_one(
            &format!("select singleton from {schema}.access_state where singleton for share"),
            &[],
        )
        .map_err(access_db_error)?;
        self.verify(&mut tx)?;
        check_runtime_in_transaction(&mut tx, schema, mode, authority)?;
        if let Some(actor) = actor {
            lock_self_actor(&mut tx, schema, actor)?;
        }
        let mut transaction = PostgresSelfPasswordChangeReadTransaction { tx, schema };
        let result = run(&mut transaction)?;
        transaction.tx.commit().map_err(access_db_error)?;
        Ok(result)
    }

    fn password_change_write<R>(
        &self,
        mode: TenancyMode,
        authority: &str,
        actor: &AccessActor,
        run: impl FnOnce(&mut Self::WriteTransaction<'_>) -> Result<R, AccessError>,
    ) -> Result<R, AccessError> {
        if mode != self.mode {
            return Err(AccessError::ModeMismatch);
        }
        let mut client = self.adapter.connect()?;
        let mut tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .map_err(access_db_error)?;
        tx.batch_execute("set local statement_timeout='5s'; set local lock_timeout='5s'")
            .map_err(access_db_error)?;
        let schema = self.adapter.schema_name();
        tx.query_one(
            &format!("select singleton from {schema}.access_state where singleton for update"),
            &[],
        )
        .map_err(access_db_error)?;
        self.verify(&mut tx)?;
        check_runtime_in_transaction(&mut tx, schema, mode, authority)?;
        lock_self_actor(&mut tx, schema, actor)?;
        let mut transaction = PostgresSelfPasswordChangeWriteTransaction {
            read: PostgresSelfPasswordChangeReadTransaction { tx, schema },
        };
        let result = run(&mut transaction)?;
        transaction.read.tx.commit().map_err(access_db_error)?;
        Ok(result)
    }
}

fn id(value: &str) -> Result<Uuid, StoreError> {
    Uuid::parse_str(value).map_err(|_| StoreError::Conflict("security.invalid_id"))
}
fn digest(key_id: String, bytes: Vec<u8>) -> Result<SecurityDigest, StoreError> {
    Ok(SecurityDigest {
        key_id,
        bytes: bytes
            .try_into()
            .map_err(|_| StoreError::Backend("invalid security receipt".into()))?,
    })
}

impl SelfPasswordChangeReadTransaction for PostgresSelfPasswordChangeReadTransaction<'_> {
    fn actor_is_active(
        &mut self,
        actor: &AccessActor,
        now: SystemTime,
    ) -> Result<bool, StoreError> {
        self_actor_is_active(&mut self.tx, self.schema, actor, now)
    }
    fn credential_snapshot(
        &mut self,
        actor: &AccessActor,
    ) -> Result<Option<SelfPasswordCredentialSnapshot>, StoreError> {
        self.tx.query_opt(
            &format!("select id,password_hash,security_credential_version from {}.accounts where id=$1 and status='active'", self.schema),
            &[&id(&actor.subject_id)?],
        ).map_err(access_db_error)?.map(|row| {
            let version: i64 = row.get(2);
            if version <= 0 { return Err(StoreError::Backend("invalid credential version".into())); }
            Ok(SelfPasswordCredentialSnapshot {
                account_id: row.get::<_, Uuid>(0).to_string(),
                password_hash: SecretString::new(row.get::<_, String>(1)),
                credential_version: version as u64,
            })
        }).transpose()
    }
    fn receipt(
        &mut self,
        purpose: SecurityReceiptPurpose,
        operation_id: Uuid,
    ) -> Result<Option<SecurityOperationReceipt>, StoreError> {
        self.tx.query_opt(
            &format!("select account_id,secret_key_id,secret_digest,command_key_id,command_digest,completed_at_epoch,expires_at_epoch from {}.security_receipts where purpose=$1 and operation_id=$2", self.schema),
            &[&purpose.as_str(), &operation_id],
        ).map_err(access_db_error)?.map(|row| Ok(SecurityOperationReceipt {
            purpose, operation_id, account_id: row.get::<_, Uuid>(0).to_string(),
            secret_digest: digest(row.get(1), row.get(2))?,
            command_digest: digest(row.get(3), row.get(4))?,
            completed_at: time(row.get(5))?, expires_at: time(row.get(6))?,
        })).transpose()
    }
}

impl SelfPasswordChangeReadTransaction for PostgresSelfPasswordChangeWriteTransaction<'_> {
    fn actor_is_active(
        &mut self,
        actor: &AccessActor,
        now: SystemTime,
    ) -> Result<bool, StoreError> {
        self.read.actor_is_active(actor, now)
    }
    fn credential_snapshot(
        &mut self,
        actor: &AccessActor,
    ) -> Result<Option<SelfPasswordCredentialSnapshot>, StoreError> {
        self.read.credential_snapshot(actor)
    }
    fn receipt(
        &mut self,
        purpose: SecurityReceiptPurpose,
        operation_id: Uuid,
    ) -> Result<Option<SecurityOperationReceipt>, StoreError> {
        self.read.receipt(purpose, operation_id)
    }
}

impl SelfPasswordChangeWriteTransaction for PostgresSelfPasswordChangeWriteTransaction<'_> {
    fn receipt_count(&mut self) -> Result<u64, StoreError> {
        let count: i64 = self
            .read
            .tx
            .query_one(
                &format!(
                    "select count(*) from {}.security_receipts",
                    self.read.schema
                ),
                &[],
            )
            .map_err(access_db_error)?
            .get(0);
        count
            .try_into()
            .map_err(|_| StoreError::Backend("invalid security receipt count".into()))
    }

    fn replace_password_and_retire(
        &mut self,
        actor: &AccessActor,
        snapshot: &SelfPasswordCredentialSnapshot,
        new_password_hash: &SecretString,
        now: SystemTime,
    ) -> Result<(), StoreError> {
        if snapshot.account_id != actor.subject_id {
            return Err(StoreError::Conflict("security.credentials_changed"));
        }
        let version = i64::try_from(snapshot.credential_version)
            .map_err(|_| StoreError::Conflict("security.credentials_changed"))?;
        let account = id(&actor.subject_id)?;
        let now = epoch(now)?;
        let s = self.read.schema;
        let tx = &mut self.read.tx;
        let changed = tx.execute(
            &format!("update {s}.accounts set password_hash=$4 where id=$1 and status='active' and password_hash=$2 and security_credential_version=$3"),
            &[&account, &snapshot.password_hash.expose_secret(), &version, &new_password_hash.expose_secret()],
        ).map_err(access_db_error)?;
        if changed != 1 {
            return Err(StoreError::Conflict("security.credentials_changed"));
        }
        super::password_retirement::retire_account_credentials(tx, s, account, now)?;
        Ok(())
    }

    fn record_completion(
        &mut self,
        receipt: &SecurityOperationReceipt,
        event_id: Uuid,
    ) -> Result<(), StoreError> {
        if receipt.purpose != SecurityReceiptPurpose::PasswordChange {
            return Err(StoreError::Conflict("security.invalid_receipt_purpose"));
        }
        let s = self.read.schema;
        let account = id(&receipt.account_id)?;
        let now = epoch(receipt.completed_at)?;
        let expires = epoch(receipt.expires_at)?;
        self.read.tx.execute(
            &format!("insert into {s}.security_receipts(purpose,operation_id,account_id,secret_key_id,secret_digest,command_key_id,command_digest,completed_at_epoch,expires_at_epoch) values($1,$2,$3,$4,$5,$6,$7,$8,$9)"),
            &[&receipt.purpose.as_str(),&receipt.operation_id,&account,&receipt.secret_digest.key_id,&receipt.secret_digest.bytes.as_slice(),&receipt.command_digest.key_id,&receipt.command_digest.bytes.as_slice(),&now,&expires],
        ).map_err(access_db_error)?;
        self.read.tx.execute(&format!("insert into {s}.security_events(id,kind,outcome,account_id,operation_id,occurred_at_epoch) values($1,'password_changed','accepted',$2,$3,$4)"), &[&event_id,&account,&receipt.operation_id,&now]).map_err(access_db_error)?;
        Ok(())
    }
}
