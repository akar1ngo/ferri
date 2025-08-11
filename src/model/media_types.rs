//! OCI Image Media Types
//!
//! The following media types identify the formats described in the OCI Image Specification
//! and their referenced resources.

/// Content Descriptor media type
pub const DESCRIPTOR: &str = "application/vnd.oci.descriptor.v1+json";

/// OCI Layout Header media type
pub const LAYOUT_HEADER: &str = "application/vnd.oci.layout.header.v1+json";

/// Image Index media type
pub const IMAGE_INDEX: &str = "application/vnd.oci.image.index.v1+json";

/// Image Manifest media type
pub const IMAGE_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

/// Image Config media type
pub const IMAGE_CONFIG: &str = "application/vnd.oci.image.config.v1+json";

/// Layer media type (tar archive)
pub const LAYER_TAR: &str = "application/vnd.oci.image.layer.v1.tar";

/// Layer media type (tar archive compressed with gzip)
pub const LAYER_TAR_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

/// Non-distributable layer media type (tar archive)
pub const LAYER_NONDISTRIBUTABLE_TAR: &str = "application/vnd.oci.image.layer.nondistributable.v1.tar";

/// Non-distributable layer media type (tar archive compressed with gzip)
pub const LAYER_NONDISTRIBUTABLE_TAR_GZIP: &str = "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip";

/* Docker compatibility media types */

/// Docker manifest list media type (similar to OCI Image Index)
pub const DOCKER_MANIFEST_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";

/// Docker manifest media type (similar to OCI Image Manifest)
pub const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";

/// Docker layer media type (interchangeable with OCI layer tar+gzip)
pub const DOCKER_LAYER_GZIP: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";

/// Docker config media type (similar to OCI Image Config)
pub const DOCKER_CONFIG: &str = "application/vnd.docker.container.image.v1+json";

/// Check if a media type is a valid config media type
pub fn is_config_media_type(media_type: &str) -> bool {
    matches!(media_type, IMAGE_CONFIG)
}

/// Check if a media type is a valid layer media type
pub fn is_layer_media_type(media_type: &str) -> bool {
    matches!(
        media_type,
        LAYER_TAR | LAYER_TAR_GZIP | LAYER_NONDISTRIBUTABLE_TAR | LAYER_NONDISTRIBUTABLE_TAR_GZIP
    )
}

/// Check if a media type is a valid manifest media type
pub fn is_manifest_media_type(media_type: &str) -> bool {
    matches!(media_type, IMAGE_MANIFEST)
}

/// Check if a media type is a valid index media type
pub fn is_index_media_type(media_type: &str) -> bool {
    matches!(media_type, IMAGE_INDEX)
}

/// Check if a media type is Docker-compatible for layers
pub fn is_docker_compatible_layer(media_type: &str) -> bool {
    matches!(media_type, DOCKER_LAYER_GZIP | LAYER_TAR_GZIP)
}
