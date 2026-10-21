use super::*;
impl<C: RegistrationEmailCrypto> PostgresRegistrationEmailStore<C> {
    pub(super) fn next_delivery_inner(&self) -> Result<Option<Uuid>, RegistrationEmailError> {
        let mut c = self
            .adapter
            .connect()
            .map_err(RegistrationEmailError::Store)?;
        let mut tx = c.transaction().map_err(db)?;
        self.tx_begin(&mut tx)?;
        self.require_runtime_open(&mut tx)?;
        let row=tx.query_opt(&format!("select d.id from {} d join {} x on x.id=d.context_id where x.authority=$1 and x.product=$2 and x.tenant_id=$3 and d.status='reserved' order by d.id limit 1",self.table("deliveries"),self.table("contexts")),&[&self.scope.authority,&self.scope.product,&self.scope.tenant]).map_err(db)?;
        tx.commit().map_err(db)?;
        Ok(row.map(|r| r.get(0)))
    }
    pub(super) fn delivery_message_inner(
        &self,
        claim: &RegistrationEmailDeliveryClaim,
    ) -> Result<Option<RegistrationEmailMessage>, RegistrationEmailError> {
        let mut c = self
            .adapter
            .connect()
            .map_err(RegistrationEmailError::Store)?;
        let mut tx = c.transaction().map_err(db)?;
        self.tx_begin(&mut tx)?;
        self.require_runtime_open(&mut tx)?;
        let row=tx.query_opt(&format!("select d.*,x.expires_at,x.current_seq,x.accepted_seq,x.completed_operation,i.kind,i.operation_id from {} d join {} x on x.id=d.context_id join {} i on i.context_id=d.context_id and i.seq=d.seq where d.id=$1 and x.authority=$2 and x.product=$3 and x.tenant_id=$4 for update of d",self.table("deliveries"),self.table("contexts"),self.table("intents")),&[&claim.effect_id,&self.scope.authority,&self.scope.product,&self.scope.tenant]).map_err(db)?.ok_or(RegistrationEmailError::Unavailable)?;
        if row.get::<_, String>("status") != "claimed"
            || row.get::<_, Option<Uuid>>("claim_token") != Some(claim.claim_token)
            || row.get::<_, Uuid>("context_id") != claim.context_id
            || row.get::<_, i64>("seq") != claim.sequence
            || row.get::<_, Option<i64>>("lease_until") != Some(claim.lease_until)
        {
            return Err(RegistrationEmailError::Unavailable);
        }
        // Empty ciphertext means this claim has already handed its message to a worker.
        // It does not prove the physical call has stopped, even after lease expiry.
        let ciphertext: Vec<u8> = row.get("payload_cipher");
        if ciphertext.is_empty() {
            return Err(RegistrationEmailError::Unavailable);
        }
        let at = now(&mut tx)?;
        if at >= claim.lease_until
            || row.get::<_, i64>("expires_at") <= at
            || row.get::<_, Option<i64>>("current_seq") != Some(claim.sequence)
            || row.get::<_, i64>("accepted_seq") != claim.sequence
            || row.get::<_, Option<Uuid>>("completed_operation").is_some()
        {
            tx.execute(&format!("update {} set status='expired',payload_cipher=''::bytea,stop_confirmed=true where id=$1",self.table("deliveries")),&[&claim.effect_id]).map_err(db)?;
            let kind = match row.get::<_, String>("kind").as_str() {
                "register" => RegistrationEmailOperationKind::Register,
                "resend" => RegistrationEmailOperationKind::Resend,
                _ => return Err(RegistrationEmailError::Unavailable),
            };
            self.event(
                &mut tx,
                row.get("operation_id"),
                kind,
                None,
                Some(claim.context_id),
                "expired",
                at,
            )?;
            tx.commit().map_err(db)?;
            return Ok(None);
        }
        let bytes = self
            .crypto
            .open("delivery", &self.scope, &claim.context_id, &ciphertext)?;
        let mut rest = bytes.as_slice();
        let mut take = || -> Result<String, RegistrationEmailError> {
            if rest.len() < 4 {
                return Err(RegistrationEmailError::Unavailable);
            }
            let n = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
            if n > 1024 || rest.len() < n + 4 {
                return Err(RegistrationEmailError::Unavailable);
            }
            let v = std::str::from_utf8(&rest[4..4 + n])
                .map_err(|_| RegistrationEmailError::Unavailable)?
                .to_string();
            rest = &rest[4 + n..];
            Ok(v)
        };
        let email = take()?;
        let code = take()?;
        let expiry = take()?
            .parse::<i64>()
            .map_err(|_| RegistrationEmailError::Unavailable)?;
        if !rest.is_empty()
            || expiry != row.get::<_, i64>("expires_at")
            || CanonicalRegistrationEmail::parse(&email).is_err()
            || code.len() != 6
            || !code.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(RegistrationEmailError::Unavailable);
        }
        if now(&mut tx)? >= claim.lease_until {
            return Err(RegistrationEmailError::Unavailable);
        }
        let remaining:i64=tx.query_one("select greatest(0,floor(($1::bigint-extract(epoch from clock_timestamp()))*1000))::bigint",&[&claim.lease_until]).map_err(db)?.get(0);
        let taken=tx.execute(&format!("update {} d set payload_cipher=''::bytea where id=$1 and context_id=$2 and seq=$3 and claim_token=$4 and lease_until=$5 and status='claimed' and octet_length(payload_cipher)>0 and exists(select 1 from {} x where x.id=d.context_id and x.current_seq=d.seq and x.accepted_seq=d.seq and x.completed_operation is null and x.expires_at>floor(extract(epoch from clock_timestamp())) and d.lease_until>floor(extract(epoch from clock_timestamp())))",self.table("deliveries"),self.table("contexts")),&[&claim.effect_id,&claim.context_id,&claim.sequence,&claim.claim_token,&claim.lease_until]).map_err(db)?;
        if taken != 1 {
            return Err(RegistrationEmailError::Unavailable);
        }
        let kind = match row.get::<_, String>("kind").as_str() {
            "register" => RegistrationEmailOperationKind::Register,
            "resend" => RegistrationEmailOperationKind::Resend,
            _ => return Err(RegistrationEmailError::Unavailable),
        };
        self.event(
            &mut tx,
            row.get("operation_id"),
            kind,
            None,
            Some(claim.context_id),
            "message_taken",
            at,
        )?;
        tx.commit().map_err(db)?;
        Ok(Some(RegistrationEmailMessage {
            email: SecretString::new(email),
            code: SecretString::new(code),
            expires_at_unix_secs: expiry,
            lease_remaining_millis: remaining as u64,
        }))
    }
}
