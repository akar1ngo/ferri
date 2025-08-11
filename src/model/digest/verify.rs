use hmac_sha256::Hash;
use thiserror::Error;

use super::Digest;

#[derive(Debug, Error, PartialEq)]
pub enum DigestError {
    #[error("digest mismatch")]
    Mismatch,
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,
}

pub type DigestResult = Result<(), DigestError>;

impl Digest {
    pub fn verify(&self, input: &[u8]) -> DigestResult {
        match self {
            Digest::Sha256(encoded) => verify_sha256(encoded, input),
            Digest::Sha512(_) => Err(DigestError::UnsupportedAlgorithm),
            Digest::Other(_, _) => Err(DigestError::UnsupportedAlgorithm),
        }
    }
}

fn verify_sha256(expected: &str, input: &[u8]) -> DigestResult {
    let mut hasher = Hash::new();
    hasher.update(input);

    if hex::encode(hasher.finalize()) == expected {
        Ok(())
    } else {
        Err(DigestError::Mismatch)
    }
}

#[cfg(test)]
mod tests {
    use crate::model::digest::{DigestError, parse_digest};

    #[test]
    fn verify_ok() {
        let string = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let digest = parse_digest(string).expect("digest string must be valid");

        assert!(digest.verify(b"").is_ok());
    }

    #[test]
    fn verify_mismatch() {
        let string = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let digest = parse_digest(string).expect("digest string must be valid");
        let result = digest.verify(b"hoge");

        assert_eq!(result.unwrap_err(), DigestError::Mismatch);
    }

    #[test]
    fn verify_unsupported() {
        let string = "sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        let digest = parse_digest(string).expect("digest string must be valid");
        let result = digest.verify(b"hoge");

        assert_eq!(result.unwrap_err(), DigestError::UnsupportedAlgorithm);
    }
}
