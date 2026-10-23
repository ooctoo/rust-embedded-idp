use super::{Client, Error, Transaction};
use tokio_postgres::{types::ToSql, Row};

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Client {}
    impl Sealed for super::Transaction<'_> {}
}

/// The closed SQL subset shared by an owned connection and native transaction.
/// Hosts no longer depend on the foreign synchronous driver's sealed trait.
pub trait Executor: sealed::Sealed {
    fn query(&mut self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Vec<Row>, Error>;
    fn query_one(&mut self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Row, Error>;
    fn query_opt(
        &mut self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<Row>, Error>;
    fn execute(&mut self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<u64, Error>;
    fn batch_execute(&mut self, sql: &str) -> Result<(), Error>;
}

macro_rules! executor {
    ($ty:ty) => {
        impl Executor for $ty {
            fn query(&mut self, sql: &str, p: &[&(dyn ToSql + Sync)]) -> Result<Vec<Row>, Error> {
                self.query(sql, p)
            }
            fn query_one(&mut self, sql: &str, p: &[&(dyn ToSql + Sync)]) -> Result<Row, Error> {
                self.query_one(sql, p)
            }
            fn query_opt(
                &mut self,
                sql: &str,
                p: &[&(dyn ToSql + Sync)],
            ) -> Result<Option<Row>, Error> {
                self.query_opt(sql, p)
            }
            fn execute(&mut self, sql: &str, p: &[&(dyn ToSql + Sync)]) -> Result<u64, Error> {
                self.execute(sql, p)
            }
            fn batch_execute(&mut self, sql: &str) -> Result<(), Error> {
                self.batch_execute(sql)
            }
        }
    };
}
executor!(Client);
executor!(Transaction<'_>);
