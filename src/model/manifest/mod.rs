//! Implements the `application/vnd.oci.image.manifest.v1+json` media type as
//! defined in OCI Image Manifest Specification v1.0.1.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{Descriptor, DescriptorError, media_types};

/// Image Manifest provides a configuration and set of layers for a single container
/// image for a specific architecture and operating system.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct ImageManifest {
    /// This REQUIRED property specifies the image manifest schema version.
    /// For this version of the specification, this MUST be `2`.
    #[serde(rename = "schemaVersion")]
    pub schema_version: u8,

    /// This property is reserved for use, to maintain compatibility.
    /// When used, this field contains the media type of this document.
    #[serde(rename = "mediaType", skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,

    /// This REQUIRED property references a configuration object for a container, by digest.
    pub config: Descriptor,

    /// Each item in the array MUST be a descriptor.
    /// The array MUST have the base layer at index 0.
    /// Subsequent layers MUST then follow in stack order.
    pub layers: Vec<Descriptor>,

    /// This OPTIONAL property contains arbitrary metadata for the image manifest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
}

impl ImageManifest {
    /// Creates a new ImageManifest with the required fields.
    pub fn new(config: Descriptor, layers: Vec<Descriptor>) -> Self {
        Self {
            schema_version: 2,
            media_type: Some(media_types::IMAGE_MANIFEST.to_string()),
            config,
            layers,
            annotations: None,
        }
    }

    /// Validates the manifest according to the specification.
    pub fn validate(&self) -> Result<(), ManifestError> {
        // Validate schema version
        if self.schema_version != 2 {
            return Err(ManifestError::InvalidSchemaVersion(self.schema_version));
        }

        // Validate config descriptor
        self.config.validate().map_err(ManifestError::InvalidConfig)?;

        // Validate that config has the correct media type
        if !is_valid_config_media_type(&self.config.media_type) {
            return Err(ManifestError::InvalidConfigMediaType(self.config.media_type.clone()));
        }

        // Validate all layer descriptors
        for (idx, layer) in self.layers.iter().enumerate() {
            layer.validate().map_err(|e| ManifestError::InvalidLayer(idx, e))?;

            // Validate that layer has the correct media type
            if !is_valid_layer_media_type(&layer.media_type) {
                return Err(ManifestError::InvalidLayerMediaType(idx, layer.media_type.clone()));
            }
        }

        Ok(())
    }

    /// Adds an annotation to the manifest.
    pub fn add_annotation(&mut self, key: String, value: String) {
        self.annotations.get_or_insert_with(BTreeMap::new).insert(key, value);
    }

    /// Sets the media type for the manifest.
    pub fn set_media_type(&mut self, media_type: String) {
        self.media_type = Some(media_type);
    }
}

/// Errors that can occur when working with Image Manifests.
#[derive(Error, Debug)]
pub enum ManifestError {
    #[error("Invalid schema version: {0}, expected 2")]
    InvalidSchemaVersion(u8),

    #[error("Invalid config descriptor")]
    InvalidConfig(#[from] DescriptorError),

    #[error("Invalid config media type: {0}")]
    InvalidConfigMediaType(String),

    #[error("Invalid layer descriptor at index {0}")]
    InvalidLayer(usize, DescriptorError),

    #[error("Invalid layer media type at index {0}: {1}")]
    InvalidLayerMediaType(usize, String),
}

/// Check if a media type is valid for a config descriptor.
fn is_valid_config_media_type(media_type: &str) -> bool {
    media_types::is_config_media_type(media_type)
}

/// Check if a media type is valid for a layer descriptor.
fn is_valid_layer_media_type(media_type: &str) -> bool {
    media_types::is_layer_media_type(media_type)
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;
    use crate::model::digest::parse_digest;

    fn create_test_descriptor(media_type: &str, digest: &str, size: u64) -> Descriptor {
        Descriptor {
            media_type: media_type.to_string(),
            digest: parse_digest(digest).unwrap(),
            size,
            urls: None,
            annotations: None,
        }
    }

    #[test]
    fn test_manifest_creation() -> Result<(), Box<dyn Error>> {
        let config = create_test_descriptor(
            media_types::IMAGE_CONFIG,
            "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7",
            7023,
        );

        let layers = vec![
            create_test_descriptor(
                media_types::LAYER_TAR_GZIP,
                "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0",
                32654,
            ),
            create_test_descriptor(
                media_types::LAYER_TAR_GZIP,
                "sha256:3c3a4604a545cdc127456d94e421cd355bca5b528f4a9c1905b15da2eb4a4c6b",
                16724,
            ),
        ];

        let manifest = ImageManifest::new(config, layers);
        assert_eq!(manifest.schema_version, 2);
        assert_eq!(manifest.layers.len(), 2);

        manifest.validate()?;
        Ok(())
    }

    #[test]
    fn test_manifest_with_annotations() -> Result<(), Box<dyn Error>> {
        let config = create_test_descriptor(
            media_types::IMAGE_CONFIG,
            "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7",
            7023,
        );

        let layers = vec![create_test_descriptor(
            media_types::LAYER_TAR_GZIP,
            "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0",
            32654,
        )];

        let mut manifest = ImageManifest::new(config, layers);
        manifest.add_annotation("com.example.key1".to_string(), "value1".to_string());
        manifest.add_annotation("com.example.key2".to_string(), "value2".to_string());

        assert!(manifest.annotations.is_some());
        let annotations = manifest.annotations.as_ref().unwrap();
        assert_eq!(annotations.get("com.example.key1"), Some(&"value1".to_string()));
        assert_eq!(annotations.get("com.example.key2"), Some(&"value2".to_string()));

        manifest.validate()?;
        Ok(())
    }

    #[test]
    fn test_manifest_serialization() -> Result<(), Box<dyn Error>> {
        let config = create_test_descriptor(
            media_types::IMAGE_CONFIG,
            "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7",
            7023,
        );

        let layers = vec![create_test_descriptor(
            media_types::LAYER_TAR_GZIP,
            "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0",
            32654,
        )];

        let mut manifest = ImageManifest::new(config, layers);
        manifest.add_annotation("com.example.key1".to_string(), "value1".to_string());

        let json = serde_json::to_string_pretty(&manifest)?;
        let deserialized: ImageManifest = serde_json::from_str(&json)?;

        assert_eq!(manifest, deserialized);
        Ok(())
    }

    #[test]
    fn test_manifest_validation_errors() {
        let config = create_test_descriptor(
            media_types::IMAGE_CONFIG,
            "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7",
            7023,
        );

        let layers = vec![create_test_descriptor(
            media_types::LAYER_TAR_GZIP,
            "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0",
            32654,
        )];

        // Test invalid schema version
        let mut manifest = ImageManifest::new(config.clone(), layers.clone());
        manifest.schema_version = 1;
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::InvalidSchemaVersion(1))
        ));

        // Test invalid config media type
        let invalid_config = create_test_descriptor(
            media_types::DOCKER_CONFIG, // Wrong media type
            "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7",
            7023,
        );
        let manifest = ImageManifest::new(invalid_config, layers.clone());
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::InvalidConfigMediaType(_))
        ));

        // Test invalid layer media type
        let invalid_layer = create_test_descriptor(
            media_types::DOCKER_LAYER_GZIP, // Wrong media type
            "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0",
            32654,
        );
        let manifest = ImageManifest::new(config, vec![invalid_layer]);
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::InvalidLayerMediaType(0, _))
        ));
    }

    #[test]
    fn test_example_from_spec() -> Result<(), Box<dyn Error>> {
        let json = r#"{
          "schemaVersion": 2,
          "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": 7023,
            "digest": "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7"
          },
          "layers": [
            {
              "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
              "size": 32654,
              "digest": "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0"
            },
            {
              "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
              "size": 16724,
              "digest": "sha256:3c3a4604a545cdc127456d94e421cd355bca5b528f4a9c1905b15da2eb4a4c6b"
            },
            {
              "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
              "size": 73109,
              "digest": "sha256:ec4b8955958665577945c89419d1af06b5f7636b4ac3da7f12184802ad867736"
            }
          ],
          "annotations": {
            "com.example.key1": "value1",
            "com.example.key2": "value2"
          }
        }"#;

        let manifest: ImageManifest = serde_json::from_str(json)?;
        manifest.validate()?;

        assert_eq!(manifest.schema_version, 2);
        assert_eq!(manifest.layers.len(), 3);
        assert!(manifest.annotations.is_some());

        let serialized = serde_json::to_string(&manifest)?;
        let roundtrip: ImageManifest = serde_json::from_str(&serialized)?;
        assert_eq!(manifest, roundtrip);

        Ok(())
    }
}
