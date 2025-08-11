//! Sample data generation for testing registry operations
//!
//! This module provides utilities to create sample OCI images, manifests,
//! and blobs for testing the distribution registry functionality.

use std::io::Write;

use digest::Digest;
use hmac_sha256::Hash;

use crate::model::config::{Config, ImageConfig, Rootfs};
use crate::model::descriptor::Descriptor;
use crate::model::digest::parse_digest;
use crate::model::manifest::ImageManifest;
use crate::model::media_types;

/// Creates a simple TAR archive with a single empty file
pub fn create_sample_layer() -> Vec<u8> {
    let mut tar_data = Vec::new();

    // Create a simple TAR header for an empty file named "empty.txt"
    let mut header = [0u8; 512];

    // File name (100 bytes, null-terminated)
    let filename = b"empty.txt";
    header[..filename.len()].copy_from_slice(filename);

    // File mode (8 bytes, octal)
    let mode = b"0000644\0";
    header[100..108].copy_from_slice(mode);

    // Owner UID (8 bytes, octal)
    let uid = b"0001750\0";
    header[108..116].copy_from_slice(uid);

    // Owner GID (8 bytes, octal)
    let gid = b"0001750\0";
    header[116..124].copy_from_slice(gid);

    // File size (12 bytes, octal) - 0 for empty file
    let size = b"00000000000\0";
    header[124..136].copy_from_slice(size);

    // Modification time (12 bytes, octal)
    let mtime = b"14000000000\0";
    header[136..148].copy_from_slice(mtime);

    // Checksum placeholder (8 bytes)
    header[148..156].fill(b' ');

    // File type (1 byte) - '0' for regular file
    header[156] = b'0';

    // Calculate checksum
    let checksum: u32 = header.iter().map(|&b| b as u32).sum();
    let checksum_str = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(checksum_str.as_bytes());

    tar_data.extend_from_slice(&header);

    // Add two 512-byte blocks of zeros to mark end of archive
    tar_data.extend_from_slice(&[0u8; 1024]);

    tar_data
}

/// Creates a gzipped version of the sample layer
pub fn create_sample_layer_gzipped() -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let layer_data = create_sample_layer();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&layer_data).unwrap();
    encoder.finish().unwrap()
}

/// Creates a sample image configuration with a given layer digest
pub fn create_sample_config(layer_digest: &str) -> ImageConfig {
    let diff_ids = vec![layer_digest.to_string()];
    let rootfs = Rootfs::new(diff_ids);

    let mut image_config = ImageConfig::new("amd64".to_string(), "linux".to_string(), rootfs);

    image_config.set_created("2025-01-01T00:00:00Z".to_string());
    image_config.set_author("Your Name <your.email@example.com>".to_string());

    let mut config = Config::new();
    config.add_env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    config.add_env("LANG", "C.UTF-8");
    config.working_dir = Some("/app".to_string());
    config.cmd = Some(vec!["/bin/sh".to_string()]);

    image_config.set_config(config);

    image_config
}

/// Creates a sample image manifest with given config and layer descriptors
pub fn create_sample_manifest(config_descriptor: Descriptor, layer_descriptors: Vec<Descriptor>) -> ImageManifest {
    let mut manifest = ImageManifest::new(config_descriptor, layer_descriptors);
    manifest.add_annotation("org.opencontainers.image.title".to_string(), "Sample Image".to_string());
    manifest.add_annotation(
        "org.opencontainers.image.description".to_string(),
        "A sample OCI image for testing".to_string(),
    );
    manifest.add_annotation("org.opencontainers.image.version".to_string(), "1.0.0".to_string());

    manifest
}

/// Sample repository and image data for testing
pub struct SampleImage {
    pub repository: String,
    pub tag: String,
    pub config: ImageConfig,
    pub config_blob: Vec<u8>,
    pub config_digest: String,
    pub manifest: ImageManifest,
    pub manifest_blob: Vec<u8>,
    pub layer_blob: Vec<u8>,
    pub layer_digest: String,
}

impl SampleImage {
    /// Creates a complete sample image with all components
    pub fn create(repository: &str, tag: &str) -> Self {
        // First create the layer and its digest
        let layer_blob = create_sample_layer_gzipped();
        let layer_digest = format!("sha256:{}", hex::encode(Hash::digest(&layer_blob)));

        // Create config with the correct layer digest
        let config = create_sample_config(&layer_digest);
        let config_blob = serde_json::to_vec(&config).unwrap();
        let config_digest = format!("sha256:{}", hex::encode(Hash::digest(&config_blob)));

        // Create descriptors with correct digests and sizes
        let config_descriptor = Descriptor {
            media_type: media_types::IMAGE_CONFIG.to_string(),
            digest: parse_digest(&config_digest).unwrap(),
            size: config_blob.len() as u64,
            urls: None,
            annotations: None,
        };

        let layer_descriptor = Descriptor {
            media_type: media_types::LAYER_TAR_GZIP.to_string(),
            digest: parse_digest(&layer_digest).unwrap(),
            size: layer_blob.len() as u64,
            urls: None,
            annotations: None,
        };

        // Create manifest with the correct descriptors
        let manifest = create_sample_manifest(config_descriptor, vec![layer_descriptor]);
        let manifest_blob = serde_json::to_vec(&manifest).unwrap();

        Self {
            repository: repository.to_string(),
            tag: tag.to_string(),
            config,
            config_blob,
            config_digest,
            manifest,
            manifest_blob,
            layer_blob,
            layer_digest,
        }
    }

    /// Creates a sample "hello-world" image
    pub fn hello_world() -> Self {
        Self::create("hello-world", "latest")
    }

    /// Creates a sample "alpine" image
    pub fn alpine() -> Self {
        Self::create("alpine", "latest")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_sample_layer() {
        let layer = create_sample_layer();
        assert!(!layer.is_empty());
        // TAR files should be at least 1024 bytes (512 for header + 512*2 for end markers)
        assert!(layer.len() >= 1024);
        // Should end with two blocks of zeros
        assert_eq!(&layer[layer.len() - 1024..], &[0u8; 1024]);
    }

    #[test]
    fn test_create_sample_layer_gzipped() {
        let gzipped = create_sample_layer_gzipped();
        assert!(!gzipped.is_empty());
        // Gzipped data should start with gzip magic number
        assert_eq!(&gzipped[0..2], &[0x1f, 0x8b]);
    }

    #[test]
    fn test_create_sample_config() {
        let layer_digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let config = create_sample_config(layer_digest);
        assert_eq!(config.architecture, "amd64");
        assert_eq!(config.os, "linux");
        assert!(config.config.is_some());
        assert!(config.created.is_some());
        config.validate().unwrap();
    }

    #[test]
    fn test_create_sample_manifest() {
        // Create sample descriptors for testing
        let config_descriptor = Descriptor {
            media_type: media_types::IMAGE_CONFIG.to_string(),
            digest: parse_digest("sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7").unwrap(),
            size: 1024,
            urls: None,
            annotations: None,
        };

        let layer_descriptor = Descriptor {
            media_type: media_types::LAYER_TAR_GZIP.to_string(),
            digest: parse_digest("sha256:c6f988f4874bb0add23a778f753c65efe992244e148a1d2ec2a8b664fb66bbd1").unwrap(),
            size: 2048,
            urls: None,
            annotations: None,
        };

        let manifest = create_sample_manifest(config_descriptor, vec![layer_descriptor]);
        assert_eq!(manifest.schema_version, 2);
        assert_eq!(manifest.layers.len(), 1);
        assert!(manifest.annotations.is_some());
        manifest.validate().unwrap();
    }

    #[test]
    fn test_sample_image() {
        let sample = SampleImage::hello_world();
        assert_eq!(sample.repository, "hello-world");
        assert_eq!(sample.tag, "latest");
        assert!(!sample.config_blob.is_empty());
        assert!(!sample.manifest_blob.is_empty());
        assert!(!sample.layer_blob.is_empty());
        assert!(sample.config_digest.starts_with("sha256:"));
        assert!(sample.layer_digest.starts_with("sha256:"));

        // Validate components
        sample.config.validate().unwrap();
        sample.manifest.validate().unwrap();
    }
}
