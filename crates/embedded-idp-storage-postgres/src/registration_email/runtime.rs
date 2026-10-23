mod claims;
mod delivery;
mod health;
use super::{support::*, *};
use embedded_idp_core::{PasswordWorkBudget, SecretString};
impl<C: RegistrationEmailCrypto + 'static> RegistrationEmailService
    for PostgresRegistrationEmailStore<C>
{
    fn scope(&self) -> &RegistrationEmailScope {
        &self.scope
    }
    fn policy(&self) -> &RegistrationEmailPolicy {
        &self.policy
    }
    fn password_work_budget(&self) -> PasswordWorkBudget {
        self.password_budget.clone()
    }
    fn runtime_facts(&self) -> Result<RegistrationEmailRuntimeFacts, RegistrationEmailError> {
        self.runtime_facts_inner()
    }
    fn is_replay(
        &self,
        kind: RegistrationEmailOperationKind,
        operation: Uuid,
    ) -> Result<bool, RegistrationEmailError> {
        let mut c = self.connect_readonly()?;
        let mut tx = c.transaction().map_err(db)?;
        tx.batch_execute("set transaction read only; set local transaction_timeout='5s'; set local statement_timeout='5s'; set local lock_timeout='1s'").map_err(db)?;
        check_registration_operation_freshness(&operation, now(&mut tx)?)?;
        let replay = self
            .operation(&mut tx, kind, operation)?
            .is_some_and(|r| r.get::<_, String>("phase") == "attached");
        tx.commit().map_err(db)?;
        Ok(replay)
    }
    fn register_command(
        &self,
        cmd: RegistrationEmailCommand,
    ) -> Result<RegistrationEmailAccepted, RegistrationEmailError> {
        let email = CanonicalRegistrationEmail::parse(cmd.email.expose_secret())?;
        let name = cmd.display_name.as_ref().map(|v| v.expose_secret());
        if name.is_some_and(|s| {
            s.is_empty() || s.chars().count() > 128 || s.chars().any(char::is_control)
        }) {
            return Err(RegistrationEmailError::InvalidInput("display_name"));
        }
        let payload = fields(&[
            email.identity().as_bytes(),
            cmd.password.expose_secret().as_bytes(),
            name.unwrap_or("").as_bytes(),
        ]);
        let digest = self.crypto.request_digest(
            &self.scope,
            RegistrationEmailOperationKind::Register,
            &cmd.operation,
            &payload,
        );
        if let Some(row) = self.early_operation(
            RegistrationEmailOperationKind::Register,
            cmd.operation,
            &digest,
        )? {
            let mut c = self.connect_readonly()?;
            let mut tx = c.transaction().map_err(db)?;
            tx.batch_execute("set transaction read only; set local transaction_timeout='5s'; set local statement_timeout='5s'; set local lock_timeout='1s'").map_err(db)?;
            let accepted = self.acceptance(&mut tx, &row)?;
            tx.commit().map_err(db)?;
            return Ok(accepted);
        }
        let facts = self.runtime_facts_inner()?;
        if !facts.store_ready
            || !facts.accepting
            || facts.overdue_processing > 0
            || facts.unresolved_delivery > 0
        {
            return Err(RegistrationEmailError::RegistrationClosed);
        }
        let _permit = self
            .password_budget
            .try_registration()
            .map_err(RegistrationEmailError::Store)?;
        let prepared = PreparedRegistrationEmail::prepare(
            &self.scope,
            self.crypto.as_ref(),
            cmd.operation,
            email.identity(),
            &cmd.password,
            name,
        )?;
        self.register(&prepared)
    }
    fn resend_command(&self, operation: Uuid, token: &str) -> Result<(), RegistrationEmailError> {
        if !self.runtime_facts_inner()?.store_ready {
            return Err(RegistrationEmailError::Unavailable);
        }
        self.resend(operation, token)
    }
    fn verify_command(
        &self,
        operation: Uuid,
        token: &str,
        code: &str,
    ) -> Result<RegistrationEmailVerification, RegistrationEmailError> {
        if !self.runtime_facts_inner()?.store_ready {
            return Err(RegistrationEmailError::Unavailable);
        }
        self.verify(operation, token, code)
    }
    fn claim_preparation(
        &self,
    ) -> Result<Option<RegistrationEmailPreparationClaim>, RegistrationEmailError> {
        self.claim_next_preparation()
    }
    fn prepare_claimed(
        &self,
        claim: &RegistrationEmailPreparationClaim,
    ) -> Result<RegistrationEmailPreparation, RegistrationEmailError> {
        self.prepare_claimed_inner(claim)
    }
    fn next_delivery(&self) -> Result<Option<Uuid>, RegistrationEmailError> {
        self.next_delivery_inner()
    }
    fn claim_delivery(
        &self,
        effect: Uuid,
    ) -> Result<Option<RegistrationEmailDeliveryClaim>, RegistrationEmailError> {
        PostgresRegistrationEmailStore::claim_delivery(self, effect)
    }
    fn delivery_message(
        &self,
        claim: &RegistrationEmailDeliveryClaim,
    ) -> Result<Option<RegistrationEmailMessage>, RegistrationEmailError> {
        self.delivery_message_inner(claim)
    }
    fn finish_delivery(
        &self,
        claim: &RegistrationEmailDeliveryClaim,
        result: RegistrationEmailDeliveryResult,
    ) -> Result<(), RegistrationEmailError> {
        PostgresRegistrationEmailStore::finish_delivery(self, claim, result)
    }
    fn confirm_delivery_stopped(
        &self,
        claim: &RegistrationEmailDeliveryClaim,
    ) -> Result<(), RegistrationEmailError> {
        PostgresRegistrationEmailStore::confirm_delivery_stopped(self, claim)
    }
    fn pause_registration(&self) -> Result<(), RegistrationEmailError> {
        self.set_paused(true)
    }
    fn resume_registration(&self) -> Result<(), RegistrationEmailError> {
        self.set_paused(false)
    }
    fn maintain_runtime(&self) -> Result<(), RegistrationEmailError> {
        self.maintain_runtime_inner()
    }
}
