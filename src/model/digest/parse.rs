use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Takes string and returns a parsed Digest type. When parsing fails, returns
/// a ParseDigestError explaining what went wrong.
pub fn parse_digest(input: &str) -> Result<Digest, ParseDigestError> {
    StateMachine::parse(input)
}

/// A parsed digest string. Conforms to OCI Content Descriptors v1.0.1.
#[derive(Debug, Clone, PartialEq)]
pub enum Digest {
    Sha256(String),
    Sha512(String),
    Other(String, String),
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Digest::Sha256(encoded) => write!(f, "sha256:{encoded}"),
            Digest::Sha512(encoded) => write!(f, "sha512:{encoded}"),
            Digest::Other(algorithm, encoded) => write!(f, "{algorithm}:{encoded}"),
        }
    }
}

/// Error describing what exactly went wrong when parsing a digest string.
#[derive(Error, Debug)]
pub enum ParseDigestError {
    #[error("input is empty")]
    EmptyInput,

    #[error("missing ':' after algorithm")]
    MissingColon,

    #[error("algorithm component is empty (separator at position {0})")]
    EmptyAlgorithmComponent(usize),

    #[error("encoded portion is empty (':' at position {0})")]
    EmptyEncodedComponent(usize),

    #[error("unexpected character '{ch}' at position {pos} while in state {context:?}")]
    UnexpectedChar {
        pos: usize,
        ch: char,
        context: &'static str,
    },

    #[error("hash verification failed")]
    VerificationError,
}

struct StateMachine<'a> {
    input: &'a str,
    colon_pos: usize,
    state: State,
}

impl<'a> StateMachine<'a> {
    fn parse(input: &'a str) -> Result<Digest, ParseDigestError> {
        let mut sm = StateMachine {
            input,
            colon_pos: usize::MAX, // sentinel: no colon seen yet
            state: State::StartAlgorithm,
        };

        for (idx, byte) in input.bytes().enumerate() {
            sm.next_state(idx, byte)?;
        }

        sm.finish()
    }

    #[inline]
    fn next_state(&mut self, idx: usize, byte: u8) -> Result<(), ParseDigestError> {
        use State::*;

        self.state = match self.state {
            // expect the first character of the first algorithm component
            StartAlgorithm => {
                if is_algorithm_component(byte) {
                    Algorithm
                } else {
                    return Err(ParseDigestError::UnexpectedChar {
                        pos: idx,
                        ch: byte as char,
                        context: self.state.as_str(),
                    });
                }
            }

            // read the remainder of an algorithm component
            Algorithm => {
                if is_algorithm_component(byte) {
                    Algorithm
                } else if is_algorithm_separator(byte) {
                    AfterSeparator
                } else if byte == b':' {
                    self.colon_pos = idx;
                    AfterColon
                } else {
                    return Err(ParseDigestError::UnexpectedChar {
                        pos: idx,
                        ch: byte as char,
                        context: self.state.as_str(),
                    });
                }
            }

            // the last byte read was a separator
            // we now expect the first byte of the next algorithm component
            AfterSeparator => {
                if is_algorithm_component(byte) {
                    Algorithm
                } else {
                    return Err(ParseDigestError::EmptyAlgorithmComponent(idx));
                }
            }

            // the last byte read was the mandatory colon separator
            // we now expect the first character of the encoded part
            AfterColon => {
                if is_encoded_character(byte) {
                    Encoded
                } else {
                    return Err(ParseDigestError::EmptyEncodedComponent(idx));
                }
            }

            // read the remainder of the encoded part
            Encoded => {
                if is_encoded_character(byte) {
                    Encoded
                } else {
                    return Err(ParseDigestError::UnexpectedChar {
                        pos: idx,
                        ch: byte as char,
                        context: self.state.as_str(),
                    });
                }
            }
        };

        Ok(())
    }

    fn finish(self) -> Result<Digest, ParseDigestError> {
        use State::*;
        match self.state {
            StartAlgorithm => Err(ParseDigestError::EmptyInput),
            Algorithm | AfterSeparator => Err(ParseDigestError::MissingColon),
            AfterColon => Err(ParseDigestError::EmptyEncodedComponent(self.input.len())),
            Encoded => {
                let colon = self.colon_pos;
                let algorithm = &self.input[..colon];
                let encoded = &self.input[colon + 1..];

                match algorithm {
                    "sha256" => {
                        // the encoded portion MUST match /[a-f0-9]{64}/.
                        if encoded.len() != 64 || !encoded.bytes().all(is_hex) {
                            return Err(ParseDigestError::VerificationError);
                        }
                        Ok(Digest::Sha256(encoded.to_owned()))
                    }

                    "sha512" => {
                        // the encoded portion MUST match /[a-f0-9]{128}/.
                        if encoded.len() != 128 || !encoded.bytes().all(is_hex) {
                            return Err(ParseDigestError::VerificationError);
                        }
                        Ok(Digest::Sha512(encoded.to_owned()))
                    }

                    _ => Ok(Digest::Other(algorithm.to_owned(), encoded.to_owned())),
                }
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum State {
    StartAlgorithm,
    Algorithm,
    AfterSeparator,
    AfterColon,
    Encoded,
}

impl State {
    fn as_str(self) -> &'static str {
        match self {
            State::StartAlgorithm => "StartAlgorithm",
            State::Algorithm => "Algorithm",
            State::AfterSeparator => "AfterSeparator",
            State::AfterColon => "AfterColon",
            State::Encoded => "Encoded",
        }
    }
}

#[inline]
fn is_algorithm_component(b: u8) -> bool {
    // algorithm-component ::= [a-z0-9]+
    matches!(b, b'a'..=b'z' | b'0'..=b'9')
}

#[inline]
fn is_algorithm_separator(b: u8) -> bool {
    // algorithm-separator ::= [+._-]
    matches!(b, b'+' | b'.' | b'_' | b'-')
}

#[inline]
fn is_encoded_character(b: u8) -> bool {
    // encoded ::= [a-zA-Z0-9=_-]+
    matches!(b,
        b'a'..=b'z' |
        b'A'..=b'Z' |
        b'0'..=b'9' |
        b'=' |
        b'_' |
        b'-'
    )
}

#[inline]
fn is_hex(b: u8) -> bool {
    // From the specification: Note that [A-F] MUST NOT be used here.
    matches!(b, b'a'..=b'f' | b'0'..=b'9')
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        parse_digest(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) {
        assert!(parse_digest(s).is_ok(), "expected Ok for {s}");
    }

    fn err(s: &str) {
        assert!(parse_digest(s).is_err(), "expected Err for {s}");
    }

    #[test]
    fn valid_digests() {
        ok("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        ok(
            "sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        );
        ok("multihash+base58:QmRZxt2b1FVZPNqd8hsiykDL3TdBDeTSPX9Kv46HmX4Gx8");
        ok("sha256+b64u:LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564");
    }

    #[test]
    fn invalid_algorithm() {
        err(""); // empty
        err("sha256"); // no colon
        err(":abcd"); // missing algorithm
        err("sha@:abcd"); // invalid char '@'
        err("sha-:abcd"); // empty component
    }

    #[test]
    fn invalid_encoded() {
        err(""); // empty
        err("sha256:"); // empty encoded
        err("sha256:abc/def"); // '/' not allowed
    }

    #[test]
    fn invalid_hash_length() {
        err("sha256:abc");
        err("sha512:abc");
    }

    #[test]
    fn invalid_hex_chars() {
        // 'g' is not hex
        err("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85g");

        // 'z' is not hex
        err(
            "sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3z",
        );
    }

    #[test]
    fn test_digest_serialization_roundtrip() {
        let test_cases = vec![
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            "multihash+base58:QmRZxt2b1FVZPNqd8hsiykDL3TdBDeTSPX9Kv46HmX4Gx8",
            "sha256+b64u:LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564",
        ];

        for digest_str in test_cases {
            let digest = parse_digest(digest_str).expect("should parse valid digest");
            let json = serde_json::to_string(&digest).expect("should serialize to JSON");
            let expected_json = format!("\"{digest_str}\"");
            assert_eq!(json, expected_json);

            let deserialized: Digest = serde_json::from_str(&json).expect("should deserialize from JSON");

            assert_eq!(digest, deserialized);
            assert_eq!(digest.to_string(), digest_str);
        }
    }
}
