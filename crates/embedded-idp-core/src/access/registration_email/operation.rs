/// The three registration operations share one authority and budget model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegistrationEmailOperationKind {
    Register,
    Resend,
    Verify,
}

impl RegistrationEmailOperationKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Resend => "resend",
            Self::Verify => "verify",
        }
    }
}
