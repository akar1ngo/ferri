use std::path::PathBuf;

use async_trait::async_trait;
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
    pub fn new(root: PathBuf) -> Self {
        Self { root }
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
        // Check if blob exists for mounting
        Ok(self.blob_exists(digest).await.unwrap_or(false))
    }

    async fn put_manifest(
        &self,
        _repository: &str,
        _reference: &str,
        _manifest_data: Vec<u8>,
        _content_type: String,
    ) -> DistributionResult<String> {
        todo!()
    }

    async fn get_manifest(&self, _repository: &str, _reference: &str) -> DistributionResult<ManifestEntry> {
        todo!()
    }

    async fn manifest_exists(&self, _repository: &str, _reference: &str) -> DistributionResult<bool> {
        todo!()
    }

    async fn delete_manifest(&self, _repository: &str, _reference: &str) -> DistributionResult<()> {
        todo!()
    }

    async fn list_tags(&self, _repository: &str) -> DistributionResult<Vec<String>> {
        todo!()
    }

    async fn list_repositories(&self) -> DistributionResult<Vec<String>> {
        todo!()
    }

    async fn start_upload(&self, _repository: &str) -> DistributionResult<UploadSession> {
        todo!()
    }

    async fn get_upload(&self, _uuid: &str) -> DistributionResult<UploadSession> {
        todo!()
    }

    async fn update_upload(&self, _session: UploadSession) -> DistributionResult<()> {
        todo!()
    }

    async fn complete_upload(&self, _uuid: &str, _digest: &str) -> DistributionResult<()> {
        todo!()
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
    pub fn new_filesystem(root: PathBuf) -> Self {
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
