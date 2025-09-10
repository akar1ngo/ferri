use std::collections::HashMap;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use digest::Digest;
use hmac_sha256::Hash;
use tokio::fs;

use crate::distribution::storage::{ManifestEntry, MemoryStorage, UploadSession};
use crate::distribution::{DistributionError, DistributionResult};

#[async_trait]
pub trait StorageBackend: Send + Sync + 'static {
    // Blob operations
    async fn put_blob(&self, digest: &str, data: Vec<u8>) -> DistributionResult<()>;
    async fn get_blob(&self, digest: &str) -> DistributionResult<Vec<u8>>;
    async fn blob_exists(&self, digest: &str) -> DistributionResult<bool>;
    async fn delete_blob(&self, digest: &str) -> DistributionResult<()>;
    async fn mount_blob(&self, from_repo: &str, to_repo: &str, digest: &str) -> DistributionResult<bool>;

    // Manifest operations
    async fn put_manifest(
        &self,
        repository: &str,
        reference: &str,
        manifest_data: Vec<u8>,
        content_type: String,
    ) -> DistributionResult<String>;
    async fn get_manifest(&self, repository: &str, reference: &str) -> DistributionResult<ManifestEntry>;
    async fn manifest_exists(&self, repository: &str, reference: &str) -> DistributionResult<bool>;
    async fn delete_manifest(&self, repository: &str, reference: &str) -> DistributionResult<()>;

    // Tag and repository operations
    async fn list_tags(&self, repository: &str) -> DistributionResult<Vec<String>>;
    async fn list_repositories(&self) -> DistributionResult<Vec<String>>;

    // Upload operations
    async fn start_upload(&self, repository: &str) -> DistributionResult<UploadSession>;
    async fn get_upload(&self, uuid: &str) -> DistributionResult<UploadSession>;
    async fn update_upload(&self, session: UploadSession) -> DistributionResult<()>;
    async fn complete_upload(&self, uuid: &str, digest: &str) -> DistributionResult<()>;
}

#[async_trait]
impl StorageBackend for MemoryStorage {
    async fn put_blob(&self, digest: &str, data: Vec<u8>) -> DistributionResult<()> {
        MemoryStorage::put_blob(self, digest, data)
    }

    async fn get_blob(&self, digest: &str) -> DistributionResult<Vec<u8>> {
        MemoryStorage::get_blob(self, digest)
    }

    async fn blob_exists(&self, digest: &str) -> DistributionResult<bool> {
        MemoryStorage::blob_exists(self, digest)
    }

    async fn delete_blob(&self, digest: &str) -> DistributionResult<()> {
        MemoryStorage::delete_blob(self, digest)
    }

    async fn mount_blob(&self, from_repo: &str, to_repo: &str, digest: &str) -> DistributionResult<bool> {
        MemoryStorage::mount_blob(self, from_repo, to_repo, digest)
    }

    async fn put_manifest(
        &self,
        repository: &str,
        reference: &str,
        manifest_data: Vec<u8>,
        content_type: String,
    ) -> DistributionResult<String> {
        MemoryStorage::put_manifest(self, repository, reference, manifest_data, content_type)
    }

    async fn get_manifest(&self, repository: &str, reference: &str) -> DistributionResult<ManifestEntry> {
        MemoryStorage::get_manifest(self, repository, reference)
    }

    async fn manifest_exists(&self, repository: &str, reference: &str) -> DistributionResult<bool> {
        MemoryStorage::manifest_exists(self, repository, reference)
    }

    async fn delete_manifest(&self, repository: &str, reference: &str) -> DistributionResult<()> {
        MemoryStorage::delete_manifest(self, repository, reference)
    }

    async fn list_tags(&self, repository: &str) -> DistributionResult<Vec<String>> {
        MemoryStorage::list_tags(self, repository)
    }

    async fn list_repositories(&self) -> DistributionResult<Vec<String>> {
        MemoryStorage::list_repositories(self)
    }

    async fn start_upload(&self, repository: &str) -> DistributionResult<UploadSession> {
        MemoryStorage::start_upload(self, repository)
    }

    async fn get_upload(&self, uuid: &str) -> DistributionResult<UploadSession> {
        MemoryStorage::get_upload(self, uuid)
    }

    async fn update_upload(&self, session: UploadSession) -> DistributionResult<()> {
        MemoryStorage::update_upload(self, session)
    }

    async fn complete_upload(&self, uuid: &str, digest: &str) -> DistributionResult<()> {
        MemoryStorage::complete_upload(self, uuid, digest)
    }
}

pub struct FileSystemStorage {
    pub root: PathBuf,
}

impl FileSystemStorage {
    pub fn new(root: &Path) -> Self {
        // TODO: avoid clone
        Self { root: root.to_owned() }
    }
}

#[async_trait]
impl StorageBackend for FileSystemStorage {
    async fn put_blob(&self, digest: &str, data: Vec<u8>) -> DistributionResult<()> {
        let blobs_dir = self.root.join("blobs");

        fs::create_dir_all(&blobs_dir)
            .await
            .map_err(|e| DistributionError::InternalError(e.to_string()))?;

        fs::write(blobs_dir.join(digest), data)
            .await
            .map_err(|e| DistributionError::InternalError(e.to_string()))?;

        Ok(())
    }

    async fn get_blob(&self, digest: &str) -> DistributionResult<Vec<u8>> {
        let p = self.root.join("blobs").join(digest);
        let b = fs::read(p)
            .await
            .map_err(|_| DistributionError::BlobUnknown(digest.to_owned()))?;

        Ok(b)
    }

    async fn blob_exists(&self, digest: &str) -> DistributionResult<bool> {
        let p = self.root.join("blobs").join(digest);
        Ok(fs::metadata(p).await.is_ok())
    }

    async fn delete_blob(&self, digest: &str) -> DistributionResult<()> {
        let p = self.root.join("blobs").join(digest);
        fs::remove_file(p)
            .await
            .map_err(|_| DistributionError::BlobUnknown(digest.to_owned()))?;

        Ok(())
    }

    async fn mount_blob(&self, _from_repo: &str, _to_repo: &str, digest: &str) -> DistributionResult<bool> {
        Ok(self.blob_exists(digest).await.unwrap_or(false))
    }

    async fn put_manifest(
        &self,
        repository: &str,
        reference: &str,
        manifest_data: Vec<u8>,
        content_type: String,
    ) -> DistributionResult<String> {
        let repo_dir = self.root.join("repositories").join(repository);
        let manifests_dir = repo_dir.join("manifests");

        fs::create_dir_all(&manifests_dir)
            .await
            .map_err(|e| DistributionError::InternalError(e.to_string()))?;

        let digest = format!("sha256:{}", hex::encode(Hash::digest(&manifest_data)));

        let manifest_entry = ManifestEntry::new(manifest_data, content_type);
        let manifest_json =
            serde_json::to_vec(&manifest_entry).map_err(|e| DistributionError::InternalError(e.to_string()))?;

        let ref_path = manifests_dir.join(reference);
        fs::write(&ref_path, &manifest_json)
            .await
            .map_err(|e| DistributionError::InternalError(e.to_string()))?;

        if !reference.starts_with("sha256:") && !reference.starts_with("sha512:") {
            let digest_path = manifests_dir.join(&digest);
            fs::write(&digest_path, &manifest_json)
                .await
                .map_err(|e| DistributionError::InternalError(e.to_string()))?;

            self.update_tag(repository, reference, &digest).await?;
        }

        Ok(digest)
    }

    async fn get_manifest(&self, repository: &str, reference: &str) -> DistributionResult<ManifestEntry> {
        let manifest_path = self
            .root
            .join("repositories")
            .join(repository)
            .join("manifests")
            .join(reference);

        let data = fs::read(&manifest_path)
            .await
            .map_err(|_| DistributionError::ManifestUnknown(reference.to_string()))?;

        let manifest_entry: ManifestEntry =
            serde_json::from_slice(&data).map_err(|e| DistributionError::InternalError(e.to_string()))?;

        Ok(manifest_entry)
    }

    async fn manifest_exists(&self, repository: &str, reference: &str) -> DistributionResult<bool> {
        let manifest_path = self
            .root
            .join("repositories")
            .join(repository)
            .join("manifests")
            .join(reference);

        Ok(fs::metadata(manifest_path).await.is_ok())
    }

    async fn delete_manifest(&self, repository: &str, reference: &str) -> DistributionResult<()> {
        let manifest_path = self
            .root
            .join("repositories")
            .join(repository)
            .join("manifests")
            .join(reference);

        fs::remove_file(&manifest_path)
            .await
            .map_err(|_| DistributionError::ManifestUnknown(reference.to_string()))?;

        // Handle tag/digest cleanup
        if reference.starts_with("sha256:") || reference.starts_with("sha512:") {
            // Deleting by digest - remove all tags pointing to this digest
            let mut tags = self.load_tags(repository).await.unwrap_or_default();
            let tags_to_remove: Vec<String> = tags
                .iter()
                .filter(|(_, digest)| *digest == reference)
                .map(|(tag, _)| tag.clone())
                .collect();

            for tag in tags_to_remove {
                tags.remove(&tag);
                // Also remove the tag-based manifest file
                let tag_manifest_path = self
                    .root
                    .join("repositories")
                    .join(repository)
                    .join("manifests")
                    .join(&tag);
                let _ = fs::remove_file(tag_manifest_path).await;
            }

            self.save_tags(repository, &tags).await?;
        } else {
            // Deleting by tag - also remove the digest-based manifest
            let mut tags = self.load_tags(repository).await.unwrap_or_default();
            if let Some(digest) = tags.remove(reference) {
                let digest_manifest_path = self
                    .root
                    .join("repositories")
                    .join(repository)
                    .join("manifests")
                    .join(&digest);
                let _ = fs::remove_file(digest_manifest_path).await;
            }
            self.save_tags(repository, &tags).await?;
        }

        Ok(())
    }

    async fn list_tags(&self, repository: &str) -> DistributionResult<Vec<String>> {
        let tags = self.load_tags(repository).await.unwrap_or_default();
        let mut tag_list: Vec<String> = tags.keys().cloned().collect();
        tag_list.sort();

        Ok(tag_list)
    }

    async fn list_repositories(&self) -> DistributionResult<Vec<String>> {
        let repos_dir = self.root.join("repositories");

        if !repos_dir.exists() {
            return Ok(Default::default());
        }

        let mut repos = Vec::new();
        let mut stack = vec![repos_dir.clone()];

        while let Some(current_dir) = stack.pop() {
            let mut entries = fs::read_dir(&current_dir)
                .await
                .map_err(|e| DistributionError::InternalError(e.to_string()))?;

            while let Some(entry) = entries
                .next_entry()
                .await
                .map_err(|e| DistributionError::InternalError(e.to_string()))?
            {
                let path = entry.path();
                if path.is_dir() {
                    let tags_file = path.join("tags.json");
                    if tags_file.exists()
                        && let Ok(repo_path) = path.strip_prefix(&repos_dir)
                        && let Some(repo_name) = repo_path.to_str()
                    {
                        repos.push(repo_name.to_string());
                    }

                    stack.push(path);
                }
            }
        }

        repos.sort();
        Ok(repos)
    }

    async fn start_upload(&self, repository: &str) -> DistributionResult<UploadSession> {
        let session = UploadSession::new(repository.to_string());
        let uploads_dir = self.root.join("uploads");

        fs::create_dir_all(&uploads_dir)
            .await
            .map_err(|e| DistributionError::InternalError(e.to_string()))?;

        let session_json = serde_json::to_vec(&session).map_err(|e| DistributionError::InternalError(e.to_string()))?;
        let session_path = uploads_dir.join(&session.uuid);

        fs::write(&session_path, session_json)
            .await
            .map_err(|e| DistributionError::InternalError(e.to_string()))?;

        Ok(session)
    }

    async fn get_upload(&self, uuid: &str) -> DistributionResult<UploadSession> {
        let session_path = self.root.join("uploads").join(uuid);

        let data = fs::read(&session_path)
            .await
            .map_err(|_| DistributionError::UploadUnknown(uuid.to_string()))?;

        let session: UploadSession =
            serde_json::from_slice(&data).map_err(|e| DistributionError::InternalError(e.to_string()))?;

        Ok(session)
    }

    async fn update_upload(&self, session: UploadSession) -> DistributionResult<()> {
        let uploads_dir = self.root.join("uploads");
        let session_path = uploads_dir.join(&session.uuid);

        let session_json = serde_json::to_vec(&session).map_err(|e| DistributionError::InternalError(e.to_string()))?;

        fs::write(&session_path, session_json)
            .await
            .map_err(|e| DistributionError::InternalError(e.to_string()))?;

        Ok(())
    }

    async fn complete_upload(&self, uuid: &str, digest: &str) -> DistributionResult<()> {
        let session_path = self.root.join("uploads").join(uuid);
        let session = self.get_upload(uuid).await?;

        let calculated_digest = format!("sha256:{}", hex::encode(Hash::digest(&session.data)));
        if calculated_digest != digest {
            return Err(DistributionError::DigestInvalid(format!(
                "Expected {digest}, got {calculated_digest}"
            )));
        }

        self.put_blob(digest, session.data).await?;

        // Clean up upload session
        fs::remove_file(&session_path)
            .await
            .map_err(|e| DistributionError::InternalError(e.to_string()))?;

        Ok(())
    }
}

impl FileSystemStorage {
    /// Load tags for a repository from the tags.json file
    async fn load_tags(&self, repository: &str) -> DistributionResult<HashMap<String, String>> {
        let tags_path = self.root.join("repositories").join(repository).join("tags.json");

        if !tags_path.exists() {
            return Ok(HashMap::new());
        }

        let data = fs::read(&tags_path)
            .await
            .map_err(|e| DistributionError::InternalError(e.to_string()))?;

        let tags: HashMap<String, String> =
            serde_json::from_slice(&data).map_err(|e| DistributionError::InternalError(e.to_string()))?;

        Ok(tags)
    }

    /// Save tags for a repository to the tags.json file
    async fn save_tags(&self, repository: &str, tags: &HashMap<String, String>) -> DistributionResult<()> {
        let repo_dir = self.root.join("repositories").join(repository);
        fs::create_dir_all(&repo_dir)
            .await
            .map_err(|e| DistributionError::InternalError(e.to_string()))?;

        let tags_path = repo_dir.join("tags.json");
        let tags_json = serde_json::to_vec_pretty(tags).map_err(|e| DistributionError::InternalError(e.to_string()))?;

        fs::write(&tags_path, tags_json)
            .await
            .map_err(|e| DistributionError::InternalError(e.to_string()))?;

        Ok(())
    }

    /// Update a single tag mapping
    async fn update_tag(&self, repository: &str, tag: &str, digest: &str) -> DistributionResult<()> {
        let mut tags = self.load_tags(repository).await.unwrap_or_default();
        tags.insert(tag.to_string(), digest.to_string());
        self.save_tags(repository, &tags).await
    }
}

pub enum StorageBackendType {
    Memory(Box<MemoryStorage>),
    FileSystem(Box<FileSystemStorage>),
}

pub struct StorageService {
    backend: StorageBackendType,
}

impl StorageService {
    /// Create in-memory storage service
    pub fn new_memory() -> Self {
        Self {
            backend: StorageBackendType::Memory(Box::default()),
        }
    }

    /// Create filesystem storage service
    pub fn new_filesystem(root: &Path) -> Self {
        Self {
            backend: StorageBackendType::FileSystem(Box::new(FileSystemStorage::new(root))),
        }
    }

    #[cfg(test)]
    pub fn as_memory_storage(&self) -> Option<&MemoryStorage> {
        match &self.backend {
            StorageBackendType::Memory(mem) => Some(mem),
            _ => None,
        }
    }

    #[cfg(test)]
    pub fn new_memory_with_sample_data() -> Self {
        let mem = MemoryStorage::new();
        mem.populate_with_sample_data().expect("Failed to populate sample data");
        Self {
            backend: StorageBackendType::Memory(Box::new(mem)),
        }
    }
}

impl StorageService {
    pub async fn put_blob(&self, digest: &str, data: Vec<u8>) -> DistributionResult<()> {
        match &self.backend {
            StorageBackendType::Memory(mem) => mem.put_blob(digest, data),
            StorageBackendType::FileSystem(fs) => fs.put_blob(digest, data).await,
        }
    }

    pub async fn get_blob(&self, digest: &str) -> DistributionResult<Vec<u8>> {
        match &self.backend {
            StorageBackendType::Memory(mem) => mem.get_blob(digest),
            StorageBackendType::FileSystem(fs) => fs.get_blob(digest).await,
        }
    }

    pub async fn blob_exists(&self, digest: &str) -> DistributionResult<bool> {
        match &self.backend {
            StorageBackendType::Memory(mem) => mem.blob_exists(digest),
            StorageBackendType::FileSystem(fs) => fs.blob_exists(digest).await,
        }
    }

    pub async fn delete_blob(&self, digest: &str) -> DistributionResult<()> {
        match &self.backend {
            StorageBackendType::Memory(mem) => mem.delete_blob(digest),
            StorageBackendType::FileSystem(fs) => fs.delete_blob(digest).await,
        }
    }

    pub async fn mount_blob(&self, from_repo: &str, to_repo: &str, digest: &str) -> DistributionResult<bool> {
        match &self.backend {
            StorageBackendType::Memory(mem) => mem.mount_blob(from_repo, to_repo, digest),
            StorageBackendType::FileSystem(fs) => fs.mount_blob(from_repo, to_repo, digest).await,
        }
    }

    pub async fn put_manifest(
        &self,
        repository: &str,
        reference: &str,
        manifest_data: Vec<u8>,
        content_type: String,
    ) -> DistributionResult<String> {
        match &self.backend {
            StorageBackendType::Memory(mem) => mem.put_manifest(repository, reference, manifest_data, content_type),
            StorageBackendType::FileSystem(fs) => {
                fs.put_manifest(repository, reference, manifest_data, content_type)
                    .await
            }
        }
    }

    pub async fn get_manifest(&self, repository: &str, reference: &str) -> DistributionResult<ManifestEntry> {
        match &self.backend {
            StorageBackendType::Memory(mem) => mem.get_manifest(repository, reference),
            StorageBackendType::FileSystem(fs) => fs.get_manifest(repository, reference).await,
        }
    }

    pub async fn manifest_exists(&self, repository: &str, reference: &str) -> DistributionResult<bool> {
        match &self.backend {
            StorageBackendType::Memory(mem) => mem.manifest_exists(repository, reference),
            StorageBackendType::FileSystem(fs) => fs.manifest_exists(repository, reference).await,
        }
    }

    pub async fn delete_manifest(&self, repository: &str, reference: &str) -> DistributionResult<()> {
        match &self.backend {
            StorageBackendType::Memory(mem) => mem.delete_manifest(repository, reference),
            StorageBackendType::FileSystem(fs) => fs.delete_manifest(repository, reference).await,
        }
    }

    pub async fn list_tags(&self, repository: &str) -> DistributionResult<Vec<String>> {
        match &self.backend {
            StorageBackendType::Memory(mem) => mem.list_tags(repository),
            StorageBackendType::FileSystem(fs) => fs.list_tags(repository).await,
        }
    }

    pub async fn list_repositories(&self) -> DistributionResult<Vec<String>> {
        match &self.backend {
            StorageBackendType::Memory(mem) => mem.list_repositories(),
            StorageBackendType::FileSystem(fs) => fs.list_repositories().await,
        }
    }

    pub async fn start_upload(&self, repository: &str) -> DistributionResult<UploadSession> {
        match &self.backend {
            StorageBackendType::Memory(mem) => mem.start_upload(repository),
            StorageBackendType::FileSystem(fs) => fs.start_upload(repository).await,
        }
    }

    pub async fn get_upload(&self, uuid: &str) -> DistributionResult<UploadSession> {
        match &self.backend {
            StorageBackendType::Memory(mem) => mem.get_upload(uuid),
            StorageBackendType::FileSystem(fs) => fs.get_upload(uuid).await,
        }
    }

    pub async fn update_upload(&self, session: UploadSession) -> DistributionResult<()> {
        match &self.backend {
            StorageBackendType::Memory(mem) => mem.update_upload(session),
            StorageBackendType::FileSystem(fs) => fs.update_upload(session).await,
        }
    }

    pub async fn complete_upload(&self, uuid: &str, digest: &str) -> DistributionResult<()> {
        match &self.backend {
            StorageBackendType::Memory(mem) => mem.complete_upload(uuid, digest),
            StorageBackendType::FileSystem(fs) => fs.complete_upload(uuid, digest).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[tokio::test]
    async fn test_filesystem_storage_basic_operations() {
        let temp_dir = TempDir::new().unwrap();
        let storage = FileSystemStorage::new(temp_dir.path());

        let digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let data = b"test data".to_vec();

        assert!(!storage.blob_exists(digest).await.unwrap());
        storage.put_blob(digest, data.clone()).await.unwrap();

        assert!(storage.blob_exists(digest).await.unwrap());
        assert_eq!(storage.get_blob(digest).await.unwrap(), data);

        let repo = "test/repo";
        let tag = "latest";
        let manifest_data = b"test manifest".to_vec();

        let manifest_digest = storage
            .put_manifest(
                repo,
                tag,
                manifest_data.clone(),
                "application/vnd.oci.image.manifest.v1+json".to_string(),
            )
            .await
            .unwrap();

        assert!(storage.manifest_exists(repo, tag).await.unwrap());
        assert_eq!(storage.get_manifest(repo, tag).await.unwrap().data, manifest_data);
        assert!(storage.manifest_exists(repo, &manifest_digest).await.unwrap());

        let tags = storage.list_tags(repo).await.unwrap();
        assert_eq!(tags, vec![tag]);

        let repos = storage.list_repositories().await.unwrap();
        assert_eq!(repos, vec![repo]);

        let upload_data = b"upload test data";
        let upload_digest = format!("sha256:{}", hex::encode(hmac_sha256::Hash::digest(upload_data)));

        let session = storage.start_upload(repo).await.unwrap();
        let uuid = session.uuid.clone();

        let mut updated_session = storage.get_upload(&uuid).await.unwrap();
        updated_session.data.extend_from_slice(upload_data);
        storage.update_upload(updated_session).await.unwrap();
        storage.complete_upload(&uuid, &upload_digest).await.unwrap();

        assert!(storage.blob_exists(&upload_digest).await.unwrap());
        assert_eq!(storage.get_blob(&upload_digest).await.unwrap(), upload_data);
        assert!(storage.get_upload(&uuid).await.is_err());
    }

    #[tokio::test]
    async fn test_storage_service_with_filesystem() {
        let temp_dir = TempDir::new().unwrap();
        let service = StorageService::new_filesystem(temp_dir.path());

        let repo = "test/service";
        let tag = "v1.0";
        let manifest_data = b"service test manifest".to_vec();

        let _digest = service
            .put_manifest(
                repo,
                tag,
                manifest_data.clone(),
                "application/vnd.oci.image.manifest.v1+json".to_string(),
            )
            .await
            .unwrap();

        assert!(service.manifest_exists(repo, tag).await.unwrap());
        assert_eq!(service.get_manifest(repo, tag).await.unwrap().data, manifest_data);

        let tags = service.list_tags(repo).await.unwrap();
        assert_eq!(tags, vec![tag]);
    }
}
