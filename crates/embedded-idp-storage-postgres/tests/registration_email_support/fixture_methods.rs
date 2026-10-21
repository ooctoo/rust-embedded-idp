use super::fixture::Fixture;
use uuid::Uuid;

impl Fixture {
    pub fn expire_delivery_claim(
        &self,
        claim: &mut embedded_idp_storage_postgres::RegistrationEmailDeliveryClaim,
    ) {
        self.adapter
            .connect()
            .expect("fixture connection")
            .execute(
                &format!(
                    "update {}.registration_email_deliveries set lease_until=0 where id=$1",
                    self.schema
                ),
                &[&claim.effect_id],
            )
            .expect("expire delivery lease");
        claim.lease_until = 0;
    }

    pub fn shift_send_timestamps(&self, seconds: i64) {
        let mut client = self.adapter.connect().expect("fixture connection");
        for table in ["registration_email_subjects", "registration_email_buckets"] {
            client
                .execute(
                    &format!(
                        "update {}.{table} set sends=coalesce((select array_agg(value-$1 order by ordinal) from unnest(sends) with ordinality as x(value,ordinal)), '{{}}'::bigint[]), last_time=greatest(last_time-$1,0)",
                        self.schema
                    ),
                    &[&seconds],
                )
                .expect("shift send timestamps");
        }
    }

    pub fn set_context_deliverable(&self, context: Uuid, value: bool) {
        self.adapter
            .connect()
            .expect("fixture connection")
            .execute(
                &format!(
                    "update {}.registration_email_contexts set deliverable=$2 where id=$1",
                    self.schema
                ),
                &[&context, &value],
            )
            .expect("set context deliverable");
    }

    pub fn set_expiry(&self, context: Uuid, code_expiry: i64, context_expiry: i64) {
        let mut client = self.adapter.connect().expect("fixture connection");
        client
            .execute(
                &format!(
                    "update {}.registration_email_contexts set accepted_at=least(accepted_at,$2::bigint-1),expires_at=$2 where id=$1",
                    self.schema
                ),
                &[&context, &context_expiry],
            )
            .expect("set context expiry");
        client
            .execute(
                &format!(
                    "update {}.registration_email_codes set issued_at=$2::bigint-1,expires_at=$2 where context_id=$1",
                    self.schema
                ),
                &[&context, &code_expiry],
            )
            .expect("set code expiry");
    }

    pub fn install_event_failure(&self) {
        let mut client = self.adapter.connect().expect("fixture connection");
        client
            .batch_execute(&format!(
                "create function {}.reject_registration_event() returns trigger language plpgsql as $$ begin raise exception 'test event failure'; end $$; create trigger reject_registration_event before insert on {}.registration_email_events for each row execute function {}.reject_registration_event()",
                self.schema, self.schema, self.schema
            ))
            .expect("event failure trigger");
    }

    pub fn drop_event_failure(&self) {
        self.adapter
            .connect()
            .expect("fixture connection")
            .batch_execute(&format!(
                "drop trigger reject_registration_event on {}.registration_email_events; drop function {}.reject_registration_event()",
                self.schema, self.schema
            ))
            .expect("drop event failure trigger");
    }
}
