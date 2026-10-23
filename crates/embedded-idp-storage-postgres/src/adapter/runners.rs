use super::*;
use crate::PostgresStoreTransaction;
use embedded_idp_core::{
    DeviceRequestVerificationError, DeviceRequestVerificationTransactionRunner,
    DeviceSecurityError, DeviceSecurityTransactionRunner, ProofBoundRefreshError,
    ProofBoundRefreshTransactionRunner, StoreTransactionRunner,
};
impl StoreTransactionRunner for PostgresStorageAdapter {
    type Transaction<'a>
        = PostgresStoreTransaction<'a>
    where
        Self: 'a;

    fn transaction<R>(
        &self,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        let mut client = self.connect()?;
        let tx = client
            .transaction()
            .map_err(|error| StoreError::Backend(format!("begin transaction failed: {error}")))?;
        let mut wrapped = PostgresStoreTransaction::new(self.schema_name(), tx);

        let result = run(&mut wrapped);
        let tx = wrapped
            .into_inner()
            .expect("postgres transaction should be present");

        match result {
            Ok(value) => {
                tx.commit().map_err(|error| {
                    StoreError::Backend(format!("commit transaction failed: {error}"))
                })?;
                Ok(value)
            }
            Err(error) => {
                tx.rollback().map_err(|rollback_error| {
                    StoreError::Backend(format!("rollback transaction failed: {rollback_error}"))
                })?;
                Err(error)
            }
        }
    }
}

impl ProofBoundRefreshTransactionRunner for PostgresStorageAdapter {
    type Transaction<'a>
        = PostgresStoreTransaction<'a>
    where
        Self: 'a;

    fn proof_bound_refresh_transaction<R>(
        &self,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, ProofBoundRefreshError>,
    ) -> Result<R, ProofBoundRefreshError> {
        let mut client = self.connect().map_err(ProofBoundRefreshError::Store)?;
        let tx = client.transaction().map_err(|error| {
            ProofBoundRefreshError::Store(StoreError::Backend(format!(
                "begin proof-bound refresh transaction failed: {error}"
            )))
        })?;
        let mut wrapped = PostgresStoreTransaction::new(self.schema_name(), tx);
        let result = run(&mut wrapped);
        let tx = wrapped
            .into_inner()
            .expect("postgres transaction should be present");

        match result {
            Ok(value) => {
                tx.commit().map_err(|error| {
                    ProofBoundRefreshError::Store(StoreError::Backend(format!(
                        "commit proof-bound refresh transaction failed: {error}"
                    )))
                })?;
                Ok(value)
            }
            Err(error) => {
                tx.rollback().map_err(|rollback_error| {
                    ProofBoundRefreshError::Store(StoreError::Backend(format!(
                        "rollback proof-bound refresh transaction failed: {rollback_error}"
                    )))
                })?;
                Err(error)
            }
        }
    }
}

impl DeviceRequestVerificationTransactionRunner for PostgresStorageAdapter {
    type Transaction<'a>
        = PostgresStoreTransaction<'a>
    where
        Self: 'a;

    fn device_request_verification_transaction<R>(
        &self,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, DeviceRequestVerificationError>,
    ) -> Result<R, DeviceRequestVerificationError> {
        let mut client = self
            .connect()
            .map_err(DeviceRequestVerificationError::Store)?;
        let tx = client.transaction().map_err(|error| {
            DeviceRequestVerificationError::Store(StoreError::Backend(format!(
                "begin device request verification transaction failed: {error}"
            )))
        })?;
        let mut wrapped = PostgresStoreTransaction::new(self.schema_name(), tx);
        let result = run(&mut wrapped);
        let tx = wrapped
            .into_inner()
            .expect("postgres transaction should be present");

        match result {
            Ok(value) => {
                tx.commit().map_err(|error| {
                    DeviceRequestVerificationError::Store(StoreError::Backend(format!(
                        "commit device request verification transaction failed: {error}"
                    )))
                })?;
                Ok(value)
            }
            Err(error) => {
                tx.rollback().map_err(|rollback_error| {
                    DeviceRequestVerificationError::Store(StoreError::Backend(format!(
                        "rollback device request verification transaction failed: {rollback_error}"
                    )))
                })?;
                Err(error)
            }
        }
    }
}

impl DeviceSecurityTransactionRunner for PostgresStorageAdapter {
    type Transaction<'a>
        = PostgresStoreTransaction<'a>
    where
        Self: 'a;

    fn device_security_transaction<R>(
        &self,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, DeviceSecurityError>,
    ) -> Result<R, DeviceSecurityError> {
        let mut client = self.connect().map_err(DeviceSecurityError::Store)?;
        let tx = client.transaction().map_err(|error| {
            DeviceSecurityError::Store(StoreError::Backend(format!(
                "begin device security transaction failed: {error}"
            )))
        })?;
        let mut wrapped = PostgresStoreTransaction::new(self.schema_name(), tx);
        let result = run(&mut wrapped);
        let tx = wrapped
            .into_inner()
            .expect("postgres transaction should be present");

        match result {
            Ok(value) => {
                tx.commit().map_err(|error| {
                    DeviceSecurityError::Store(StoreError::Backend(format!(
                        "commit device security transaction failed: {error}"
                    )))
                })?;
                Ok(value)
            }
            Err(error) => {
                tx.rollback().map_err(|rollback_error| {
                    DeviceSecurityError::Store(StoreError::Backend(format!(
                        "rollback device security transaction failed: {rollback_error}"
                    )))
                })?;
                Err(error)
            }
        }
    }
}
