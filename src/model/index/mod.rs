//! Implements the `application/vnd.oci.image.index.v1+json` media type as
//! defined in OCI Image Index Specification v1.0.1.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{Descriptor, DescriptorError, media_types};

/// Platform describes the minimum runtime requirements of the image.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Platform {
    /// This REQUIRED property specifies the CPU architecture.
    pub architecture: String,

    /// This REQUIRED property specifies the operating system.
    pub os: String,

    /// This OPTIONAL property specifies the version of the operating system
    /// targeted by the referenced blob.
    #[serde(rename = "os.version", skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,

    /// This OPTIONAL property specifies an array of strings, each specifying
    /// a mandatory OS feature.
    #[serde(rename = "os.features", skip_serializing_if = "Option::is_none")]
    pub os_features: Option<Vec<String>>,

    /// This OPTIONAL property specifies the variant of the CPU.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,

    /// This property is RESERVED for future versions of the specification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<Vec<String>>,
}

impl Platform {
    /// Creates a new Platform with the required architecture and OS.
    pub fn new(architecture: String, os: String) -> Self {
        Self {
            architecture,
            os,
            os_version: None,
            os_features: None,
            variant: None,
            features: None,
        }
    }

    /// Validates the platform according to the specification.
    pub fn validate(&self) -> Result<(), PlatformError> {
        if self.architecture.is_empty() {
            return Err(PlatformError::EmptyArchitecture);
        }

        if self.os.is_empty() {
            return Err(PlatformError::EmptyOs);
        }

        // Validate os.features for Windows
        if self.os == "windows" {
            if let Some(ref features) = self.os_features {
                for feature in features {
                    if !is_valid_windows_feature(feature) {
                        return Err(PlatformError::InvalidWindowsFeature(feature.clone()));
                    }
                }
            }
        }

        // Validate variant for ARM architectures
        if self.architecture == "arm" || self.architecture == "arm64" {
            if let Some(ref variant) = self.variant {
                if !is_valid_arm_variant(&self.architecture, variant) {
                    return Err(PlatformError::InvalidArmVariant(
                        self.architecture.clone(),
                        variant.clone(),
                    ));
                }
            }
        }

        Ok(())
    }
}

/// ManifestDescriptor extends the base Descriptor with an optional Platform.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct ManifestDescriptor {
    #[serde(flatten)]
    pub descriptor: Descriptor,

    /// This OPTIONAL property describes the minimum runtime requirements of the image.
    /// This property SHOULD be present if its target is platform-specific.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
}

impl ManifestDescriptor {
    /// Creates a new ManifestDescriptor.
    pub fn new(descriptor: Descriptor, platform: Option<Platform>) -> Self {
        Self { descriptor, platform }
    }

    /// Validates the manifest descriptor according to the specification.
    pub fn validate(&self) -> Result<(), IndexError> {
        // Validate the base descriptor
        self.descriptor.validate().map_err(IndexError::InvalidDescriptor)?;

        // Validate that the media type is correct for a manifest
        if !is_valid_manifest_media_type(&self.descriptor.media_type) {
            return Err(IndexError::InvalidManifestMediaType(self.descriptor.media_type.clone()));
        }

        // Validate the platform if present
        if let Some(ref platform) = self.platform {
            platform.validate().map_err(IndexError::InvalidPlatform)?;
        }

        Ok(())
    }
}

/// Image Index is a higher-level manifest which points to specific image manifests,
/// ideal for one or more platforms.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct ImageIndex {
    /// This REQUIRED property specifies the image manifest schema version.
    /// For this version of the specification, this MUST be `2`.
    #[serde(rename = "schemaVersion")]
    pub schema_version: u8,

    /// This property is reserved for use, to maintain compatibility.
    /// When used, this field contains the media type of this document.
    #[serde(rename = "mediaType", skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,

    /// This REQUIRED property contains a list of manifests for specific platforms.
    /// While this property MUST be present, the size of the array MAY be zero.
    pub manifests: Vec<ManifestDescriptor>,

    /// This OPTIONAL property contains arbitrary metadata for the image index.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
}

impl ImageIndex {
    /// Creates a new ImageIndex with the required fields.
    pub fn new(manifests: Vec<ManifestDescriptor>) -> Self {
        Self {
            schema_version: 2,
            media_type: Some(media_types::IMAGE_INDEX.to_string()),
            manifests,
            annotations: None,
        }
    }

    /// Creates an empty ImageIndex.
    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    /// Validates the image index according to the specification.
    pub fn validate(&self) -> Result<(), IndexError> {
        // Validate schema version
        if self.schema_version != 2 {
            return Err(IndexError::InvalidSchemaVersion(self.schema_version));
        }

        // Validate all manifest descriptors
        for (idx, manifest) in self.manifests.iter().enumerate() {
            manifest
                .validate()
                .map_err(|e| IndexError::InvalidManifest(idx, Box::new(e)))?;
        }

        Ok(())
    }

    /// Adds a manifest descriptor to the index.
    pub fn add_manifest(&mut self, manifest: ManifestDescriptor) {
        self.manifests.push(manifest);
    }

    /// Adds an annotation to the index.
    pub fn add_annotation(&mut self, key: String, value: String) {
        self.annotations.get_or_insert_with(BTreeMap::new).insert(key, value);
    }

    /// Sets the media type for the index.
    pub fn set_media_type(&mut self, media_type: String) {
        self.media_type = Some(media_type);
    }

    /// Finds manifests that match the given platform criteria.
    pub fn find_manifests_for_platform(&self, arch: &str, os: &str) -> Vec<&ManifestDescriptor> {
        self.manifests
            .iter()
            .filter(|manifest| {
                if let Some(ref platform) = manifest.platform {
                    platform.architecture == arch && platform.os == os
                } else {
                    false
                }
            })
            .collect()
    }
}

/// Errors that can occur when working with Image Indexes.
#[derive(Error, Debug)]
pub enum IndexError {
    #[error("Invalid schema version: {0}, expected 2")]
    InvalidSchemaVersion(u8),

    #[error("Invalid manifest descriptor at index {0}")]
    InvalidManifest(usize, Box<IndexError>),

    #[error("Invalid descriptor")]
    InvalidDescriptor(#[from] DescriptorError),

    #[error("Invalid manifest media type: {0}")]
    InvalidManifestMediaType(String),

    #[error("Invalid platform")]
    InvalidPlatform(#[from] PlatformError),
}

/// Errors that can occur when working with Platforms.
#[derive(Error, Debug)]
pub enum PlatformError {
    #[error("Architecture cannot be empty")]
    EmptyArchitecture,

    #[error("OS cannot be empty")]
    EmptyOs,

    #[error("Invalid Windows feature: {0}")]
    InvalidWindowsFeature(String),

    #[error("Invalid ARM variant '{1}' for architecture '{0}'")]
    InvalidArmVariant(String, String),
}

/// Check if a media type is valid for a manifest descriptor.
fn is_valid_manifest_media_type(media_type: &str) -> bool {
    media_types::is_manifest_media_type(media_type)
}

/// Check if a Windows OS feature is valid.
fn is_valid_windows_feature(feature: &str) -> bool {
    matches!(feature, "win32k")
}

/// Check if an ARM variant is valid for the given architecture.
fn is_valid_arm_variant(architecture: &str, variant: &str) -> bool {
    match architecture {
        "arm" => matches!(variant, "v6" | "v7" | "v8"),
        "arm64" => matches!(variant, "v8"),
        _ => false,
    }
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
    fn test_platform_creation() -> Result<(), Box<dyn Error>> {
        let platform = Platform::new("amd64".to_string(), "linux".to_string());
        assert_eq!(platform.architecture, "amd64");
        assert_eq!(platform.os, "linux");

        platform.validate()?;
        Ok(())
    }

    #[test]
    fn test_platform_with_variant() -> Result<(), Box<dyn Error>> {
        let mut platform = Platform::new("arm".to_string(), "linux".to_string());
        platform.variant = Some("v7".to_string());

        platform.validate()?;
        Ok(())
    }

    #[test]
    fn test_platform_validation_errors() {
        let mut platform = Platform::new("".to_string(), "linux".to_string());
        assert!(matches!(platform.validate(), Err(PlatformError::EmptyArchitecture)));

        platform.architecture = "amd64".to_string();
        platform.os = "".to_string();
        assert!(matches!(platform.validate(), Err(PlatformError::EmptyOs)));

        // Test invalid ARM variant
        platform.os = "linux".to_string();
        platform.architecture = "arm".to_string();
        platform.variant = Some("v9".to_string());
        assert!(matches!(
            platform.validate(),
            Err(PlatformError::InvalidArmVariant(_, _))
        ));
    }

    #[test]
    fn test_image_index_creation() -> Result<(), Box<dyn Error>> {
        let descriptor1 = create_test_descriptor(
            media_types::IMAGE_MANIFEST,
            "sha256:e692418e4cbaf90ca69d05a66403747baa33ee08806650b51fab815ad7fc331f",
            7143,
        );

        let platform1 = Platform::new("ppc64le".to_string(), "linux".to_string());
        let manifest1 = ManifestDescriptor::new(descriptor1, Some(platform1));

        let descriptor2 = create_test_descriptor(
            media_types::IMAGE_MANIFEST,
            "sha256:5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270",
            7682,
        );

        let platform2 = Platform::new("amd64".to_string(), "linux".to_string());
        let manifest2 = ManifestDescriptor::new(descriptor2, Some(platform2));

        let index = ImageIndex::new(vec![manifest1, manifest2]);
        assert_eq!(index.schema_version, 2);
        assert_eq!(index.manifests.len(), 2);

        index.validate()?;
        Ok(())
    }

    #[test]
    fn test_empty_image_index() -> Result<(), Box<dyn Error>> {
        let index = ImageIndex::empty();
        assert_eq!(index.manifests.len(), 0);

        index.validate()?;
        Ok(())
    }

    #[test]
    fn test_image_index_with_annotations() -> Result<(), Box<dyn Error>> {
        let descriptor = create_test_descriptor(
            media_types::IMAGE_MANIFEST,
            "sha256:e692418e4cbaf90ca69d05a66403747baa33ee08806650b51fab815ad7fc331f",
            7143,
        );

        let platform = Platform::new("amd64".to_string(), "linux".to_string());
        let manifest = ManifestDescriptor::new(descriptor, Some(platform));

        let mut index = ImageIndex::new(vec![manifest]);
        index.add_annotation("com.example.key1".to_string(), "value1".to_string());
        index.add_annotation("com.example.key2".to_string(), "value2".to_string());

        assert!(index.annotations.is_some());
        let annotations = index.annotations.as_ref().unwrap();
        assert_eq!(annotations.get("com.example.key1"), Some(&"value1".to_string()));

        index.validate()?;
        Ok(())
    }

    #[test]
    fn test_find_manifests_for_platform() -> Result<(), Box<dyn Error>> {
        let descriptor1 = create_test_descriptor(
            media_types::IMAGE_MANIFEST,
            "sha256:e692418e4cbaf90ca69d05a66403747baa33ee08806650b51fab815ad7fc331f",
            7143,
        );

        let platform1 = Platform::new("ppc64le".to_string(), "linux".to_string());
        let manifest1 = ManifestDescriptor::new(descriptor1, Some(platform1));

        let descriptor2 = create_test_descriptor(
            media_types::IMAGE_MANIFEST,
            "sha256:5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270",
            7682,
        );

        let platform2 = Platform::new("amd64".to_string(), "linux".to_string());
        let manifest2 = ManifestDescriptor::new(descriptor2, Some(platform2));

        let descriptor3 = create_test_descriptor(
            media_types::IMAGE_MANIFEST,
            "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            5000,
        );

        let platform3 = Platform::new("amd64".to_string(), "windows".to_string());
        let manifest3 = ManifestDescriptor::new(descriptor3, Some(platform3));

        let index = ImageIndex::new(vec![manifest1, manifest2, manifest3]);

        let linux_amd64 = index.find_manifests_for_platform("amd64", "linux");
        assert_eq!(linux_amd64.len(), 1);

        let windows_amd64 = index.find_manifests_for_platform("amd64", "windows");
        assert_eq!(windows_amd64.len(), 1);

        let linux_ppc64le = index.find_manifests_for_platform("ppc64le", "linux");
        assert_eq!(linux_ppc64le.len(), 1);

        let not_found = index.find_manifests_for_platform("arm64", "darwin");
        assert_eq!(not_found.len(), 0);

        Ok(())
    }

    #[test]
    fn test_image_index_serialization() -> Result<(), Box<dyn Error>> {
        let descriptor = create_test_descriptor(
            media_types::IMAGE_MANIFEST,
            "sha256:e692418e4cbaf90ca69d05a66403747baa33ee08806650b51fab815ad7fc331f",
            7143,
        );

        let platform = Platform::new("amd64".to_string(), "linux".to_string());
        let manifest = ManifestDescriptor::new(descriptor, Some(platform));

        let mut index = ImageIndex::new(vec![manifest]);
        index.add_annotation("com.example.key1".to_string(), "value1".to_string());

        let json = serde_json::to_string_pretty(&index)?;
        let deserialized: ImageIndex = serde_json::from_str(&json)?;

        assert_eq!(index, deserialized);
        Ok(())
    }

    #[test]
    fn test_example_from_spec() -> Result<(), Box<dyn Error>> {
        let json = r#"{
          "schemaVersion": 2,
          "manifests": [
            {
              "mediaType": "application/vnd.oci.image.manifest.v1+json",
              "size": 7143,
              "digest": "sha256:e692418e4cbaf90ca69d05a66403747baa33ee08806650b51fab815ad7fc331f",
              "platform": {
                "architecture": "ppc64le",
                "os": "linux"
              }
            },
            {
              "mediaType": "application/vnd.oci.image.manifest.v1+json",
              "size": 7682,
              "digest": "sha256:5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270",
              "platform": {
                "architecture": "amd64",
                "os": "linux"
              }
            }
          ],
          "annotations": {
            "com.example.key1": "value1",
            "com.example.key2": "value2"
          }
        }"#;

        let index: ImageIndex = serde_json::from_str(json)?;
        index.validate()?;

        assert_eq!(index.schema_version, 2);
        assert_eq!(index.manifests.len(), 2);
        assert!(index.annotations.is_some());

        // Check platform details
        let first_manifest = &index.manifests[0];
        assert!(first_manifest.platform.is_some());
        let platform = first_manifest.platform.as_ref().unwrap();
        assert_eq!(platform.architecture, "ppc64le");
        assert_eq!(platform.os, "linux");

        let serialized = serde_json::to_string(&index)?;
        let roundtrip: ImageIndex = serde_json::from_str(&serialized)?;
        assert_eq!(index, roundtrip);

        Ok(())
    }

    #[test]
    fn test_platform_with_windows_features() -> Result<(), Box<dyn Error>> {
        let mut platform = Platform::new("amd64".to_string(), "windows".to_string());
        platform.os_features = Some(vec!["win32k".to_string()]);

        platform.validate()?;
        Ok(())
    }

    #[test]
    fn test_platform_with_arm_variants() -> Result<(), Box<dyn Error>> {
        let mut platform = Platform::new("arm".to_string(), "linux".to_string());
        platform.variant = Some("v7".to_string());
        platform.validate()?;

        platform.variant = Some("v8".to_string());
        platform.validate()?;

        let mut platform64 = Platform::new("arm64".to_string(), "linux".to_string());
        platform64.variant = Some("v8".to_string());
        platform64.validate()?;

        Ok(())
    }
}
