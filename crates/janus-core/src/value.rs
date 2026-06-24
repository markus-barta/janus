//! Secret value wrapper.

use zeroize::Zeroize;

/// Secret bytes. No `Debug`, no `Display`.
pub struct SecretValue {
    bytes: Vec<u8>,
}

impl SecretValue {
    /// Construct from bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    /// Borrow bytes for provider/executor internals.
    ///
    /// This method is intentionally low-level; policy should decide whether a
    /// caller may reach a code path that can call it.
    pub fn expose_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_exposes_only_explicitly() {
        let value = SecretValue::new(b"secret".to_vec());
        assert_eq!(value.expose_bytes(), b"secret");
    }
}
