pub struct UploadLimits {
    pub max_blob_size: usize,
    pub max_manifest_size: usize,
}

impl Default for UploadLimits {
    fn default() -> Self {
        Self {
            max_blob_size: 1 << 30,     // 1GB
            max_manifest_size: 4 << 20, // 4MB
        }
    }
}
