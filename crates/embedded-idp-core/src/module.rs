#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleDescriptor {
    pub module_name: &'static str,
    pub crate_family: [&'static str; 3],
}

impl ModuleDescriptor {
    pub fn current() -> Self {
        Self {
            module_name: "rust-embedded-idp",
            crate_family: [
                "embedded-idp-core",
                "embedded-idp-axum",
                "embedded-idp-storage-postgres",
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainScope {
    pub auth_enabled: bool,
    pub device_enabled: bool,
    pub oidc_enabled: bool,
    pub admin_enabled: bool,
}

impl DomainScope {
    pub fn v0_1() -> Self {
        Self {
            auth_enabled: true,
            device_enabled: true,
            oidc_enabled: true,
            admin_enabled: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DomainScope, ModuleDescriptor};

    #[test]
    fn module_descriptor_lists_expected_crate_family() {
        let descriptor = ModuleDescriptor::current();

        assert_eq!(descriptor.module_name, "rust-embedded-idp");
        assert_eq!(descriptor.crate_family[0], "embedded-idp-core");
        assert_eq!(descriptor.crate_family[2], "embedded-idp-storage-postgres");
    }

    #[test]
    fn v0_1_scope_enables_auth_device_and_oidc() {
        let scope = DomainScope::v0_1();

        assert!(scope.auth_enabled);
        assert!(scope.device_enabled);
        assert!(scope.oidc_enabled);
        assert!(!scope.admin_enabled);
    }
}
