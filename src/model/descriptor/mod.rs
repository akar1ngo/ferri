//! Implements the `application/vnd.oci.descriptor.v1+json` media type as
//! defined in OCI Content Descriptors v1.0.1.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::Digest;
use crate::model::digest::{ParseDigestError, parse_digest};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Descriptor {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: Digest,
    pub size: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub urls: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
}

impl Descriptor {
    pub fn validate(&self) -> Result<(), DescriptorError> {
        if let Err(e) = parse_digest(&self.digest.to_string()) {
            return Err(DescriptorError::InvalidDigest(e));
        }

        if self.size == 0 {
            return Err(DescriptorError::ZeroSize);
        }

        // TODO: when mediaType == "application/vnd.oci.image.manifest.v1+json"
        // we want to validate the `platform` field.

        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum DescriptorError {
    #[error("Invalid digest")]
    InvalidDigest(ParseDigestError),
    #[error("Size must be greater than 0")]
    ZeroSize,
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;
    use crate::model::digest;

    #[test]
    fn test_roundtrip() -> Result<(), Box<dyn Error>> {
        let json = r#"{
          "mediaType": "application/vnd.oci.image.manifest.v1+json",
          "size": 7682,
          "digest": "sha256:5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270"
        }"#;

        let d: Descriptor = serde_json::from_str(json)?;
        let out = serde_json::to_string(&d)?;
        assert_eq!(serde_json::from_str::<Descriptor>(&out)?, d);

        Ok(())
    }

    #[test]
    fn test_descriptor_validation_and_roundtrip() -> Result<(), Box<dyn Error>> {
        let json = r#"{
          "mediaType": "application/vnd.oci.image.manifest.v1+json",
          "size": 7682,
          "digest": "sha256:5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270",
          "urls": ["https://example.com/manifest"],
          "annotations": {"org.opencontainers.image.title": "Example Image"}
        }"#;

        let descriptor: Descriptor = serde_json::from_str(json)?;
        descriptor.validate()?;

        let serialized = serde_json::to_string_pretty(&descriptor)?;
        let descriptor2: Descriptor = serde_json::from_str(&serialized)?;

        assert_eq!(descriptor, descriptor2);

        assert_eq!(
            descriptor.digest.to_string(),
            "sha256:5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270"
        );

        Ok(())
    }

    #[test]
    fn test_descriptor_validation_errors() {
        let mut descriptor = Descriptor {
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            digest: digest::parse_digest("sha256:5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270")
                .unwrap(),
            size: 0,
            urls: None,
            annotations: None,
        };

        assert!(matches!(descriptor.validate(), Err(DescriptorError::ZeroSize)));

        // Fix size, should be valid now
        descriptor.size = 1024;
        assert!(descriptor.validate().is_ok());
    }
}
