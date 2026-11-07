use keyring::{Entry, Error as KeyringError};

const KEYCHAIN_SERVICE: &str = "com.pixart.cyberaudit.desktop";
const SECRET_BYTES: usize = 32;
const SECRET_HEX_LENGTH: usize = SECRET_BYTES * 2;

const DATABASE_PASSWORD: &str = "database-password";
const BROKER_PASSWORD: &str = "broker-password";
const JWT_SECRET: &str = "jwt-secret";
const ENCRYPTION_KEY: &str = "encryption-key";
const BOOTSTRAP_TOKEN: &str = "bootstrap-token";

pub trait SecretStore {
    fn get(&self, account: &str) -> Result<Option<String>, SecretStoreError>;
    fn set(&self, account: &str, value: &str) -> Result<(), SecretStoreError>;
}

pub struct OsSecretStore;

impl SecretStore for OsSecretStore {
    fn get(&self, account: &str) -> Result<Option<String>, SecretStoreError> {
        let entry = Entry::new(KEYCHAIN_SERVICE, account).map_err(map_keyring_error)?;
        match entry.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(error) => Err(map_keyring_error(error)),
        }
    }

    fn set(&self, account: &str, value: &str) -> Result<(), SecretStoreError> {
        let entry = Entry::new(KEYCHAIN_SERVICE, account).map_err(map_keyring_error)?;
        entry.set_password(value).map_err(map_keyring_error)
    }
}

fn map_keyring_error(error: KeyringError) -> SecretStoreError {
    match error {
        KeyringError::NoEntry => SecretStoreError::NotFound,
        _ => SecretStoreError::Unavailable,
    }
}

#[derive(Clone)]
pub struct InstallationSecrets {
    database_password: String,
    broker_password: String,
    jwt_secret: String,
    encryption_key: String,
    bootstrap_token: String,
}

impl InstallationSecrets {
    pub(crate) fn database_password(&self) -> &str {
        &self.database_password
    }

    pub(crate) fn broker_password(&self) -> &str {
        &self.broker_password
    }

    pub(crate) fn jwt_secret(&self) -> &str {
        &self.jwt_secret
    }

    pub(crate) fn encryption_key(&self) -> &str {
        &self.encryption_key
    }

    pub(crate) fn bootstrap_token(&self) -> &str {
        &self.bootstrap_token
    }
}

pub fn provision_installation_secrets(
    store: &dyn SecretStore,
) -> Result<InstallationSecrets, SecretStoreError> {
    Ok(InstallationSecrets {
        database_password: get_or_create(store, DATABASE_PASSWORD)?,
        broker_password: get_or_create(store, BROKER_PASSWORD)?,
        jwt_secret: get_or_create(store, JWT_SECRET)?,
        encryption_key: get_or_create(store, ENCRYPTION_KEY)?,
        bootstrap_token: get_or_create(store, BOOTSTRAP_TOKEN)?,
    })
}

fn get_or_create(
    store: &dyn SecretStore,
    account: &'static str,
) -> Result<String, SecretStoreError> {
    if let Some(existing) = store.get(account)? {
        if is_valid_secret(&existing) {
            return Ok(existing);
        }
        return Err(SecretStoreError::InvalidValue(account));
    }

    let value = random_secret()?;
    store.set(account, &value)?;
    Ok(value)
}

fn random_secret() -> Result<String, SecretStoreError> {
    let mut secret = [0_u8; SECRET_BYTES];
    getrandom::fill(&mut secret).map_err(|_| SecretStoreError::Random)?;
    Ok(secret
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>())
}

fn is_valid_secret(value: &str) -> bool {
    value.len() == SECRET_HEX_LENGTH && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SecretStoreError {
    #[error("the requested credential does not exist")]
    NotFound,
    #[error("the operating system credential store is unavailable")]
    Unavailable,
    #[error("credential {0} has an invalid format")]
    InvalidValue(&'static str),
    #[error("secure random generation failed")]
    Random,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemorySecretStore {
        values: Mutex<HashMap<String, String>>,
    }

    impl SecretStore for MemorySecretStore {
        fn get(&self, account: &str) -> Result<Option<String>, SecretStoreError> {
            Ok(self
                .values
                .lock()
                .expect("memory secret store should not be poisoned")
                .get(account)
                .cloned())
        }

        fn set(&self, account: &str, value: &str) -> Result<(), SecretStoreError> {
            self.values
                .lock()
                .expect("memory secret store should not be poisoned")
                .insert(account.to_owned(), value.to_owned());
            Ok(())
        }
    }

    #[test]
    fn provisions_stable_distinct_installation_secrets() {
        let store = MemorySecretStore::default();
        let first = provision_installation_secrets(&store).expect("secrets should provision");
        let second = provision_installation_secrets(&store).expect("secrets should be reused");

        assert_eq!(first.database_password(), second.database_password());
        assert_eq!(first.broker_password(), second.broker_password());
        assert_eq!(first.jwt_secret(), second.jwt_secret());
        assert_eq!(first.encryption_key(), second.encryption_key());
        assert_eq!(first.bootstrap_token(), second.bootstrap_token());
        assert_ne!(first.database_password(), first.broker_password());
        assert!(is_valid_secret(first.jwt_secret()));
    }

    #[test]
    fn refuses_to_rotate_a_malformed_existing_secret() {
        let store = MemorySecretStore::default();
        store
            .set(JWT_SECRET, "short")
            .expect("fixture should be stored");

        let result = provision_installation_secrets(&store);

        assert!(matches!(
            result,
            Err(SecretStoreError::InvalidValue(JWT_SECRET))
        ));
        assert_eq!(
            store.get(JWT_SECRET).expect("fixture should be readable"),
            Some("short".to_owned())
        );
    }
}
