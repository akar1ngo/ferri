//! In-memory storage backend for the OCI Distribution registry
//!
//! This module provides a simple in-memory storage implementation for testing
//! and development purposes. In a production environment, this would be replaced
//! with persistent storage backends like filesystem, S3, or database storage.

use std::collections::HashMap;
use std::sync::RwLock;

use digest::Digest;
use hmac_sha256::Hash;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::distribution::{DistributionError, DistributionResult};

/// Represents an ongoing blob upload session
#[derive(Clone, Serialize, Deserialize)]
pub struct UploadSession {
    pub uuid: String,
    pub repository: String,
    pub data: Vec<u8>,
    pub offset: usize,
}

impl UploadSession {
    pub fn new(repository: String) -> Self {
        Self {
            uuid: Uuid::new_v4().to_string(),
            repository,
            data: Vec::new(),
            offset: 0,
        }
    }
}

/// Manifest metadata including content type
#[derive(Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub data: Vec<u8>,
    pub content_type: String,
}

impl ManifestEntry {
    pub fn new(data: Vec<u8>, content_type: String) -> Self {
        Self { data, content_type }
    }
}

/// In-memory storage backend for registry data
pub struct MemoryStorage {
    /// Stores blobs by digest
    blobs: RwLock<HashMap<String, Vec<u8>>>,
    /// Stores manifests by repository and reference (tag or digest)
    manifests: RwLock<HashMap<String, ManifestEntry>>,
    /// Stores tags by repository
    tags: RwLock<HashMap<String, HashMap<String, String>>>, // repo -> tag -> digest
    /// Stores ongoing upload sessions
    uploads: RwLock<HashMap<String, UploadSession>>,
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStorage {
    /// Creates a new in-memory storage backend
    pub fn new() -> Self {
        Self {
            blobs: RwLock::new(HashMap::new()),
            manifests: RwLock::new(HashMap::new()),
            tags: RwLock::new(HashMap::new()),
            uploads: RwLock::new(HashMap::new()),
        }
    }

    /// Stores a blob with the given digest
    pub fn put_blob(&self, digest: &str, data: Vec<u8>) -> DistributionResult<()> {
        let mut blobs = self
            .blobs
            .write()
            .map_err(|_| DistributionError::InternalError("Failed to acquire write lock".to_string()))?;
        blobs.insert(digest.to_string(), data);
        Ok(())
    }

    /// Retrieves a blob by digest
    pub fn get_blob(&self, digest: &str) -> DistributionResult<Vec<u8>> {
        let blobs = self
            .blobs
            .read()
            .map_err(|_| DistributionError::InternalError("Failed to acquire read lock".to_string()))?;
        blobs
            .get(digest)
            .cloned()
            .ok_or_else(|| DistributionError::BlobUnknown(digest.to_string()))
    }

    /// Checks if a blob exists
    pub fn blob_exists(&self, digest: &str) -> DistributionResult<bool> {
        let blobs = self
            .blobs
            .read()
            .map_err(|_| DistributionError::InternalError("Failed to acquire read lock".to_string()))?;
        Ok(blobs.contains_key(digest))
    }

    /// Stores a manifest for a repository and reference
    pub fn put_manifest(
        &self,
        repository: &str,
        reference: &str,
        manifest_data: Vec<u8>,
        content_type: String,
    ) -> DistributionResult<String> {
        let manifest_key = format!("{repository}/manifests/{reference}");

        // Calculate digest of the manifest
        let digest = format!("sha256:{}", hex::encode(Hash::digest(&manifest_data)));

        let manifest_entry = ManifestEntry::new(manifest_data.clone(), content_type);

        let mut manifests = self
            .manifests
            .write()
            .map_err(|_| DistributionError::InternalError("Failed to acquire write lock".to_string()))?;
        manifests.insert(manifest_key.clone(), manifest_entry.clone());

        // Also store by digest
        let digest_key = format!("{repository}/manifests/{digest}");
        manifests.insert(digest_key, manifest_entry);

        // If reference is not a digest, store it as a tag
        if !reference.starts_with("sha256:") && !reference.starts_with("sha512:") {
            let mut tags = self
                .tags
                .write()
                .map_err(|_| DistributionError::InternalError("Failed to acquire write lock".to_string()))?;
            tags.entry(repository.to_string())
                .or_insert_with(HashMap::new)
                .insert(reference.to_string(), digest.clone());
        }

        Ok(digest)
    }

    /// Retrieves a manifest by repository and reference
    pub fn get_manifest(&self, repository: &str, reference: &str) -> DistributionResult<ManifestEntry> {
        let manifest_key = format!("{repository}/manifests/{reference}");

        let manifests = self
            .manifests
            .read()
            .map_err(|_| DistributionError::InternalError("Failed to acquire read lock".to_string()))?;

        manifests
            .get(&manifest_key)
            .cloned()
            .ok_or_else(|| DistributionError::ManifestUnknown(reference.to_string()))
    }

    /// Checks if a manifest exists
    pub fn manifest_exists(&self, repository: &str, reference: &str) -> DistributionResult<bool> {
        let manifest_key = format!("{repository}/manifests/{reference}");

        let manifests = self
            .manifests
            .read()
            .map_err(|_| DistributionError::InternalError("Failed to acquire read lock".to_string()))?;

        Ok(manifests.contains_key(&manifest_key))
    }

    /// Lists tags for a repository
    pub fn list_tags(&self, repository: &str) -> DistributionResult<Vec<String>> {
        let tags = self
            .tags
            .read()
            .map_err(|_| DistributionError::InternalError("Failed to acquire read lock".to_string()))?;

        let repo_tags = tags
            .get(repository)
            .map(|tag_map| {
                let mut tag_list: Vec<String> = tag_map.keys().cloned().collect();
                tag_list.sort();
                tag_list
            })
            .unwrap_or_default();

        Ok(repo_tags)
    }

    /// Lists all repositories
    pub fn list_repositories(&self) -> DistributionResult<Vec<String>> {
        let tags = self
            .tags
            .read()
            .map_err(|_| DistributionError::InternalError("Failed to acquire read lock".to_string()))?;

        let mut repos: Vec<String> = tags.keys().cloned().collect();
        repos.sort();
        Ok(repos)
    }

    /// Starts a new blob upload session
    pub fn start_upload(&self, repository: &str) -> DistributionResult<UploadSession> {
        let session = UploadSession::new(repository.to_string());
        let uuid = session.uuid.clone();

        let mut uploads = self
            .uploads
            .write()
            .map_err(|_| DistributionError::InternalError("Failed to acquire write lock".to_string()))?;
        uploads.insert(uuid.clone(), session.clone());

        Ok(session)
    }

    /// Gets an upload session by UUID
    pub fn get_upload(&self, uuid: &str) -> DistributionResult<UploadSession> {
        let uploads = self
            .uploads
            .read()
            .map_err(|_| DistributionError::InternalError("Failed to acquire read lock".to_string()))?;

        uploads
            .get(uuid)
            .cloned()
            .ok_or_else(|| DistributionError::UploadUnknown(uuid.to_string()))
    }

    /// Updates an upload session (for chunked uploads)
    pub fn update_upload(&self, session: UploadSession) -> DistributionResult<()> {
        let mut uploads = self
            .uploads
            .write()
            .map_err(|_| DistributionError::InternalError("Failed to acquire write lock".to_string()))?;
        uploads.insert(session.uuid.clone(), session);
        Ok(())
    }

    /// Completes an upload session and stores the blob
    pub fn complete_upload(&self, uuid: &str, digest: &str) -> DistributionResult<()> {
        let mut uploads = self
            .uploads
            .write()
            .map_err(|_| DistributionError::InternalError("Failed to acquire write lock".to_string()))?;

        let session = uploads
            .remove(uuid)
            .ok_or_else(|| DistributionError::UploadUnknown(uuid.to_string()))?;

        // Verify digest
        let calculated_digest = format!("sha256:{}", hex::encode(Hash::digest(&session.data)));
        if calculated_digest != digest {
            return Err(DistributionError::DigestInvalid(format!(
                "Expected {digest}, got {calculated_digest}"
            )));
        }

        // Store the blob
        self.put_blob(digest, session.data)?;

        Ok(())
    }

    /// Deletes a manifest
    pub fn delete_manifest(&self, repository: &str, reference: &str) -> DistributionResult<()> {
        let manifest_key = format!("{repository}/manifests/{reference}");

        let mut manifests = self
            .manifests
            .write()
            .map_err(|_| DistributionError::InternalError("Failed to acquire write lock".to_string()))?;

        manifests
            .remove(&manifest_key)
            .ok_or_else(|| DistributionError::ManifestUnknown(reference.to_string()))?;

        // Handle tag/digest cleanup
        if reference.starts_with("sha256:") || reference.starts_with("sha512:") {
            // Deleting by digest - remove all tags pointing to this digest and the tag-based manifest entries
            let mut tags = self
                .tags
                .write()
                .map_err(|_| DistributionError::InternalError("Failed to acquire write lock".to_string()))?;

            if let Some(repo_tags) = tags.get_mut(repository) {
                // Find and remove all tags that point to this digest
                let tags_to_remove: Vec<String> = repo_tags
                    .iter()
                    .filter(|(_, digest)| digest == &reference)
                    .map(|(tag, _)| tag.clone())
                    .collect();

                for tag in tags_to_remove {
                    repo_tags.remove(&tag);
                    // Also remove the tag-based manifest entry
                    let tag_manifest_key = format!("{repository}/manifests/{tag}");
                    manifests.remove(&tag_manifest_key);
                }

                if repo_tags.is_empty() {
                    tags.remove(repository);
                }
            }
        } else {
            // Deleting by tag - also remove the digest-based manifest entry
            let mut tags = self
                .tags
                .write()
                .map_err(|_| DistributionError::InternalError("Failed to acquire write lock".to_string()))?;

            if let Some(repo_tags) = tags.get_mut(repository) {
                if let Some(digest) = repo_tags.remove(reference) {
                    // Remove the digest-based manifest entry
                    let digest_manifest_key = format!("{repository}/manifests/{digest}");
                    manifests.remove(&digest_manifest_key);
                }

                if repo_tags.is_empty() {
                    tags.remove(repository);
                }
            }
        }

        Ok(())
    }

    /// Deletes a blob
    pub fn delete_blob(&self, digest: &str) -> DistributionResult<()> {
        let mut blobs = self
            .blobs
            .write()
            .map_err(|_| DistributionError::InternalError("Failed to acquire write lock".to_string()))?;

        blobs
            .remove(digest)
            .ok_or_else(|| DistributionError::BlobUnknown(digest.to_string()))?;

        Ok(())
    }

    /// Mounts a blob from another repository
    pub fn mount_blob(&self, _from_repo: &str, _to_repo: &str, digest: &str) -> DistributionResult<bool> {
        // Check if blob exists
        if !self.blob_exists(digest)? {
            return Ok(false);
        }

        // Blob already exists, so mounting is essentially a no-op in our simple implementation
        // In a real implementation, this might involve creating references or symlinks
        Ok(true)
    }

    /// Populates storage with sample data for testing
    #[cfg(test)]
    pub fn populate_with_sample_data(&self) -> DistributionResult<()> {
        use crate::testing::sample_data::SampleImage;

        // Create hello-world sample
        let hello_world = SampleImage::hello_world();
        self.put_blob(&hello_world.config_digest, hello_world.config_blob)?;
        self.put_blob(&hello_world.layer_digest, hello_world.layer_blob)?;
        self.put_manifest(
            &hello_world.repository,
            &hello_world.tag,
            hello_world.manifest_blob,
            "application/vnd.oci.image.manifest.v1+json".to_string(),
        )?;

        // Create alpine sample
        let alpine = SampleImage::alpine();
        self.put_blob(&alpine.config_digest, alpine.config_blob)?;
        self.put_blob(&alpine.layer_digest, alpine.layer_blob)?;
        self.put_manifest(
            &alpine.repository,
            &alpine.tag,
            alpine.manifest_blob,
            "application/vnd.oci.image.manifest.v1+json".to_string(),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blob_operations() {
        let storage = MemoryStorage::new();
        let digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let data = b"test data".to_vec();

        // Test blob doesn't exist initially
        assert!(!storage.blob_exists(digest).unwrap());
        assert!(storage.get_blob(digest).is_err());

        // Store blob
        storage.put_blob(digest, data.clone()).unwrap();

        // Test blob exists and can be retrieved
        assert!(storage.blob_exists(digest).unwrap());
        assert_eq!(storage.get_blob(digest).unwrap(), data);

        // Test delete blob
        storage.delete_blob(digest).unwrap();
        assert!(!storage.blob_exists(digest).unwrap());
    }

    #[test]
    fn test_manifest_operations() {
        let storage = MemoryStorage::new();
        let repo = "test/repo";
        let tag = "latest";
        let manifest_data = b"test manifest".to_vec();

        // Test manifest doesn't exist initially
        assert!(!storage.manifest_exists(repo, tag).unwrap());
        assert!(storage.get_manifest(repo, tag).is_err());

        // Store manifest
        let digest = storage
            .put_manifest(
                repo,
                tag,
                manifest_data.clone(),
                "application/vnd.oci.image.manifest.v1+json".to_string(),
            )
            .unwrap();
        assert!(digest.starts_with("sha256:"));

        // Test manifest exists and can be retrieved
        assert!(storage.manifest_exists(repo, tag).unwrap());
        assert_eq!(storage.get_manifest(repo, tag).unwrap().data, manifest_data);

        // Test can also retrieve by digest
        assert!(storage.manifest_exists(repo, &digest).unwrap());
        assert_eq!(storage.get_manifest(repo, &digest).unwrap().data, manifest_data);

        // Test tag listing
        let tags = storage.list_tags(repo).unwrap();
        assert_eq!(tags, vec![tag]);

        // Test repository listing
        let repos = storage.list_repositories().unwrap();
        assert_eq!(repos, vec![repo]);
    }

    #[test]
    fn test_upload_operations() {
        let storage = MemoryStorage::new();
        let repo = "test/repo";
        let data = b"upload test data";
        let digest = format!("sha256:{}", hex::encode(Hash::digest(data)));

        // Start upload
        let session = storage.start_upload(repo).unwrap();
        let uuid = session.uuid.clone();

        // Simulate chunked upload
        let mut updated_session = storage.get_upload(&uuid).unwrap();
        updated_session.data.extend_from_slice(data);
        storage.update_upload(updated_session).unwrap();

        // Complete upload
        storage.complete_upload(&uuid, &digest).unwrap();

        // Verify blob was stored
        assert!(storage.blob_exists(&digest).unwrap());
        assert_eq!(storage.get_blob(&digest).unwrap(), data);

        // Verify upload session was cleaned up
        assert!(storage.get_upload(&uuid).is_err());
    }
}
