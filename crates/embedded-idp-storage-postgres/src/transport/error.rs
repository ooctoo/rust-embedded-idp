use std::fmt;

/// Safe infrastructure error; database codes remain available for existing CAS
/// and conflict handling without exposing SQL, parameters or connection data.
pub enum Error {
    Database(tokio_postgres::Error),
    Closed,
}
impl Error {
    pub fn code(&self) -> Option<&tokio_postgres::error::SqlState> {
        self.as_db_error().map(|error| error.code())
    }
    pub fn as_db_error(&self) -> Option<&tokio_postgres::error::DbError> {
        match self {
            Self::Database(error) => error.as_db_error(),
            Self::Closed => None,
        }
    }
    pub fn is_closed(&self) -> bool {
        matches!(self, Self::Closed) || matches!(self, Self::Database(error) if error.is_closed())
    }
}
impl From<tokio_postgres::Error> for Error {
    fn from(error: tokio_postgres::Error) -> Self {
        Self::Database(error)
    }
}
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("postgres transport unavailable")
    }
}
impl std::error::Error for Error {}
