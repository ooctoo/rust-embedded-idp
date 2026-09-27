//! Explicit opt-in coverage for business-admin grants and their database invariants.
use embedded_idp_core::access::*;
use embedded_idp_storage_postgres::*;
use std::env;
use uuid::Uuid;

const BUSINESS: &str = "f_01";
const OTHER_BUSINESS: &str = "f_02";

fn catalog() -> PermissionCatalog {
    PermissionCatalog::new(vec![]).unwrap()
}

struct Db {
    adapter: PostgresStorageAdapter,
    subject: Uuid,
    business_admin: Uuid,
    plain_role: Uuid,
}

impl Db {
    fn new() -> Self {
        let adapter = PostgresStorageAdapter::new(PgStorageConfig {
            connection: PgConnectionConfig {
                connection_uri: env::var("EMBEDDED_IDP_TEST_PG_CONNECTION_URI")
                    .expect("explicit test connection required"),
                schema_name: format!("idp_business_admin_it_{}", Uuid::now_v7().simple()),
                tls_mode: PgTlsMode::Disable,
                tls_ca_cert_path: None,
            },
            pool: DbPoolConfig {
                application_name: "idp-business-admin-live-test".into(),
                max_connections: 4,
                connect_timeout_secs: 3,
            },
        })
        .unwrap();
        adapter
            .initialize_access_schema(TenancyMode::Enabled, &catalog())
            .unwrap();
        let db = Self {
            adapter,
            subject: Uuid::now_v7(),
            business_admin: Uuid::now_v7(),
            plain_role: Uuid::now_v7(),
        };
        db.seed();
        db
    }

    fn schema(&self) -> &str {
        self.adapter.schema_name()
    }

    fn seed(&self) {
        let s = self.schema();
        let mut client = self.adapter.connect().unwrap();
        let mut tx = client.transaction().unwrap();
        tx.execute(
            &format!(
                "insert into {s}.access_tenants(id,kind,name,status,allow_registration,created_at_epoch) \
                 values('t1','tenant','Tenant 1','active',true,1),('t2','tenant','Tenant 2','active',true,1)"
            ),
            &[],
        )
        .unwrap();
        tx.execute(
            &format!(
                "insert into {s}.accounts(id,registration_tenant_id,email,password_hash,status,created_at_epoch) \
                 values($1,'t1','business-admin@example.test','fixture-hash','active',1)"
            ),
            &[&self.subject],
        )
        .unwrap();
        tx.execute(
            &format!(
                "insert into {s}.access_memberships(tenant_id,account_id,status,joined_at_epoch) \
                 values('t1',$1,'active',1),('t2',$1,'active',1)"
            ),
            &[&self.subject],
        )
        .unwrap();
        for (tenant, business) in [("t1", BUSINESS), ("t1", OTHER_BUSINESS), ("t2", BUSINESS)] {
            tx.execute(
                &format!(
                    "insert into {s}.access_permissions(tenant_id,business_id,resource_type,action,category,description,enabled) \
                     values($1,$2,'report','read','business','Read report',true)"
                ),
                &[&tenant, &business],
            )
            .unwrap();
        }
        tx.execute(
            &format!(
                "insert into {s}.access_roles(tenant_id,business_id,id,key,name,status,kind,created_at_epoch) \
                 values('t1',$1,$2,'business_admin','Business admin','active','business_admin',1), \
                       ('t1',$1,$3,'reader','Reader','active','business',1)"
            ),
            &[&BUSINESS, &self.business_admin, &self.plain_role],
        )
        .unwrap();
        tx.execute(
            &format!(
                "insert into {s}.access_role_bindings(id,tenant_id,business_id,account_id,role_id,scope_kind,created_at_epoch,created_by) \
                 values($1,'t1',$2,$3,$4,'business',1,$3)"
            ),
            &[&Uuid::now_v7(), &BUSINESS, &self.subject, &self.business_admin],
        )
        .unwrap();
        tx.execute(
            &format!("update {s}.access_state set bootstrap_completed_at_epoch=1"),
            &[],
        )
        .unwrap();
        tx.commit().unwrap();
    }

    fn checker(&self) -> CoreAccessService<PostgresAccessStore> {
        CoreAccessService::new(
            TenancyMode::Enabled,
            catalog(),
            PostgresAccessStore::new(self.adapter.clone(), TenancyMode::Enabled).unwrap(),
        )
    }

    fn query(&self, tenant_id: &str, business_id: &str, action: &str) -> AccessQuery {
        AccessQuery {
            tenant_id: tenant_id.into(),
            business_id: business_id.into(),
            subject_id: self.subject.to_string(),
            resource_type: "report".into(),
            action: action.into(),
            resource_id: None,
        }
    }

    fn check(&self, tenant_id: &str, business_id: &str, action: &str) -> AccessDecision {
        self.checker()
            .check(self.query(tenant_id, business_id, action))
            .unwrap()
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        assert!(self.schema().starts_with("idp_business_admin_it_"));
        if let Ok(mut client) = self.adapter.connect() {
            let _ = client.batch_execute(&format!("drop schema {} cascade", self.schema()));
        }
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn business_admin_is_exact_state_bound_and_database_guarded() {
    let db = Db::new();
    assert_eq!(db.check("t1", BUSINESS, "read"), AccessDecision::Allow);
    assert_eq!(db.check("t1", OTHER_BUSINESS, "read"), AccessDecision::Deny);
    assert_eq!(db.check("t2", BUSINESS, "read"), AccessDecision::Deny);
    assert_eq!(db.check("t1", BUSINESS, "unknown"), AccessDecision::Deny);

    let s = db.schema();
    let mut client = db.adapter.connect().unwrap();
    let state_cases = [
        (
            "account",
            format!("update {s}.accounts set status='disabled' where id=$1"),
            format!("update {s}.accounts set status='active' where id=$1"),
        ),
        (
            "membership",
            format!("update {s}.access_memberships set status='suspended' where tenant_id='t1' and account_id=$1"),
            format!("update {s}.access_memberships set status='active' where tenant_id='t1' and account_id=$1"),
        ),
        (
            "tenant",
            format!("update {s}.access_tenants set status='suspended' where id='t1'"),
            format!("update {s}.access_tenants set status='active' where id='t1'"),
        ),
        (
            "role",
            format!("update {s}.access_roles set status='disabled' where tenant_id='t1' and business_id=$1 and id=$2"),
            format!("update {s}.access_roles set status='active' where tenant_id='t1' and business_id=$1 and id=$2"),
        ),
    ];
    for (label, disable, restore) in state_cases {
        match label {
            "role" => client
                .execute(&disable, &[&BUSINESS, &db.business_admin])
                .unwrap(),
            "tenant" => client.execute(&disable, &[]).unwrap(),
            _ => client.execute(&disable, &[&db.subject]).unwrap(),
        };
        assert_eq!(
            db.check("t1", BUSINESS, "read"),
            AccessDecision::Deny,
            "{label}"
        );
        match label {
            "role" => client
                .execute(&restore, &[&BUSINESS, &db.business_admin])
                .unwrap(),
            "tenant" => client.execute(&restore, &[]).unwrap(),
            _ => client.execute(&restore, &[&db.subject]).unwrap(),
        };
        assert_eq!(
            db.check("t1", BUSINESS, "read"),
            AccessDecision::Allow,
            "{label}"
        );
    }

    for (label, disable, restore) in [
        (
            "disabled",
            format!("update {s}.access_permissions set enabled=false where tenant_id='t1' and business_id=$1 and resource_type='report' and action='read'"),
            format!("update {s}.access_permissions set enabled=true where tenant_id='t1' and business_id=$1 and resource_type='report' and action='read'"),
        ),
        (
            "archived",
            format!("update {s}.access_permissions set enabled=false, archived=true where tenant_id='t1' and business_id=$1 and resource_type='report' and action='read'"),
            format!("update {s}.access_permissions set archived=false, enabled=true where tenant_id='t1' and business_id=$1 and resource_type='report' and action='read'"),
        ),
    ] {
        client.execute(&disable, &[&BUSINESS]).unwrap();
        assert_eq!(db.check("t1", BUSINESS, "read"), AccessDecision::Deny, "{label}");
        client.execute(&restore, &[&BUSINESS]).unwrap();
    }

    client.execute(
        &format!(
            "insert into {s}.access_permissions(tenant_id,business_id,resource_type,action,category,description,enabled) \
             values('t1',$1,'report','export','business','Export report',true)"
        ),
        &[&BUSINESS],
    )
    .unwrap();
    assert_eq!(db.check("t1", BUSINESS, "export"), AccessDecision::Allow);

    assert!(client.execute(
        &format!("insert into {s}.access_permissions(tenant_id,business_id,resource_type,action,category,description,enabled) values('t1','idp.spoof','report','read','business','reserved namespace',true)"),
        &[],
    ).is_err());

    assert!(client
        .execute(
            &format!(
                "insert into {s}.access_role_bindings(id,tenant_id,business_id,account_id,role_id,scope_kind,created_at_epoch,created_by) \
                 values($1,'t1',$2,$3,$4,'business',1,$3)"
            ),
            &[&Uuid::now_v7(), &BUSINESS, &db.subject, &db.plain_role],
        )
        .is_err());
    assert!(client
        .execute(
            &format!(
                "insert into {s}.access_role_bindings(id,tenant_id,business_id,account_id,role_id,scope_kind,resource_type,created_at_epoch,created_by) \
                 values($1,'t1',$2,$3,$4,'type','report',1,$3)"
            ),
            &[&Uuid::now_v7(), &BUSINESS, &db.subject, &db.business_admin],
        )
        .is_err());
    assert!(client
        .execute(
            &format!(
                "insert into {s}.access_role_permissions(tenant_id,business_id,role_id,resource_type,action) \
                 values('t1',$1,$2,'report','read')"
            ),
            &[&BUSINESS, &db.business_admin],
        )
        .is_err());
}
