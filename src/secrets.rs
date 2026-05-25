use eyre::{eyre, Result};
use secrecy::{ExposeSecret, SecretString};
use std::str::FromStr;

fn read_env(var: &str) -> Result<String> {
    std::env::var(var).map_err(|_| eyre!("env var {var} is not set"))
}

pub struct AgeIdentity(SecretString);

impl AgeIdentity {
    /// Read identity from env, then immediately remove it from process env so any
    /// subsequently-spawned children cannot inherit it.
    pub fn take_from_env(var: &str) -> Result<Self> {
        let raw = read_env(var)?;
        std::env::remove_var(var);
        Ok(Self(SecretString::from(raw)))
    }

    pub fn parse(&self) -> Result<age::x25519::Identity> {
        let raw = self.0.expose_secret();
        // age-keygen writes a multi-line file with comment headers; GitHub
        // Secrets preserves newlines, so extract the key line explicitly.
        let key_line = raw
            .lines()
            .find(|l| l.starts_with("AGE-SECRET-KEY-"))
            .unwrap_or_else(|| raw.trim());
        age::x25519::Identity::from_str(key_line)
            .map_err(|e| eyre!("invalid age identity: {e}"))
    }
}

pub struct MinisignKey(SecretString);

impl MinisignKey {
    pub fn take_from_env(var: &str) -> Result<Self> {
        let raw = read_env(var)?;
        std::env::remove_var(var);
        Ok(Self(SecretString::from(raw)))
    }

    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

pub struct StoreCredential {
    pub access_key: SecretString,
    pub secret_key: SecretString,
}

impl StoreCredential {
    pub fn take_from_env(access_var: &str, secret_var: &str) -> Result<Self> {
        let ak = read_env(access_var)?;
        let sk = read_env(secret_var)?;
        std::env::remove_var(access_var);
        std::env::remove_var(secret_var);
        Ok(Self {
            access_key: SecretString::from(ak),
            secret_key: SecretString::from(sk),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn age_identity_parses_bare_key() {
        let identity = age::x25519::Identity::generate();
        // to_string() returns SecretBox<str> when the secrecy feature is active.
        let key_str = identity.to_string();
        let var = "TEST_AGE_BARE_52A1C3";
        std::env::set_var(var, key_str.expose_secret());
        let ai = AgeIdentity::take_from_env(var).unwrap();
        assert!(std::env::var(var).is_err(), "env var must be removed after take");
        ai.parse().expect("bare key should parse");
    }

    #[test]
    fn age_identity_parses_keygen_multiline_format() {
        let identity = age::x25519::Identity::generate();
        let key_str = identity.to_string();
        // Simulate the output of `age-keygen`: comment header lines + key line.
        let multiline = format!(
            "# created: 2024-01-01T00:00:00Z\n# public key: {}\n{}",
            identity.to_public(),
            key_str.expose_secret()
        );
        let var = "TEST_AGE_MULTILINE_52A1C3";
        std::env::set_var(var, &multiline);
        let ai = AgeIdentity::take_from_env(var).unwrap();
        assert!(std::env::var(var).is_err());
        ai.parse().expect("keygen multiline format should parse");
    }

    #[test]
    fn age_identity_missing_env_var_errors() {
        let result = AgeIdentity::take_from_env("TEST_AGE_MISSING_XYZZY_99B2D4");
        // Use .err() to avoid requiring AgeIdentity: Debug.
        let err = result.err().expect("should have returned Err");
        assert!(
            err.to_string().contains("TEST_AGE_MISSING_XYZZY_99B2D4"),
            "error should name the missing var: {err}"
        );
    }

    #[test]
    fn store_credential_clears_env_vars() {
        std::env::set_var("TEST_AK_F7E3A1", "myaccesskey");
        std::env::set_var("TEST_SK_F7E3A1", "mysecretkey");
        let cred = StoreCredential::take_from_env("TEST_AK_F7E3A1", "TEST_SK_F7E3A1").unwrap();
        assert!(std::env::var("TEST_AK_F7E3A1").is_err(), "access key var must be cleared");
        assert!(std::env::var("TEST_SK_F7E3A1").is_err(), "secret key var must be cleared");
        assert_eq!(cred.access_key.expose_secret(), "myaccesskey");
        assert_eq!(cred.secret_key.expose_secret(), "mysecretkey");
    }
}
