//! Error types for the OCI Distribution API

use actix_web::http::StatusCode;
use actix_web::{HttpResponse, ResponseError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur during distribution operations
#[derive(Error, Debug)]
pub enum DistributionError {
    #[error("Repository name is invalid: {0}")]
    NameInvalid(String),

    #[error("Repository not found: {0}")]
    NameUnknown(String),

    #[error("Manifest not found: {0}")]
    ManifestUnknown(String),

    #[error("Manifest too large")]
    ManifestTooLarge,

    #[error("Blob not found: {0}")]
    BlobUnknown(String),

    #[error("Tag is invalid: {0}")]
    TagInvalid(String),

    #[error("Digest is invalid: {0}")]
    DigestInvalid(String),

    #[error("Size is invalid")]
    SizeInvalid,

    #[error("Range is invalid")]
    RangeInvalid,

    #[error("Payload too large")]
    PayloadTooLarge,

    #[error("Upload is invalid: {0}")]
    UploadInvalid(String),

    #[error("Upload not found: {0}")]
    UploadUnknown(String),

    #[error("Unsupported media type: {0}")]
    UnsupportedMediaType(String),

    #[error("Internal server error: {0}")]
    InternalError(String),
}

/// Result type for distribution operations
pub type DistributionResult<T> = Result<T, DistributionError>;

/// Standard registry error response format
#[derive(Deserialize, Serialize)]
pub struct ErrorResponse {
    pub errors: Vec<ErrorDetail>,
}

/// Individual error detail in registry error response
#[derive(Deserialize, Serialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

impl ResponseError for DistributionError {
    fn error_response(&self) -> HttpResponse {
        let (status, code, message) = match self {
            DistributionError::NameInvalid(name) => (
                StatusCode::BAD_REQUEST,
                "NAME_INVALID",
                format!("Repository name '{name}' is invalid"),
            ),
            DistributionError::NameUnknown(name) => (
                StatusCode::NOT_FOUND,
                "NAME_UNKNOWN",
                format!("Repository '{name}' not found"),
            ),
            DistributionError::ManifestUnknown(reference) => (
                StatusCode::NOT_FOUND,
                "MANIFEST_UNKNOWN",
                format!("Manifest '{reference}' not found"),
            ),
            DistributionError::ManifestTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "MANIFEST_INVALID",
                "Manifest is too large".to_string(),
            ),
            DistributionError::BlobUnknown(digest) => (
                StatusCode::NOT_FOUND,
                "BLOB_UNKNOWN",
                format!("Blob '{digest}' not found"),
            ),
            DistributionError::TagInvalid(tag) => (
                StatusCode::BAD_REQUEST,
                "TAG_INVALID",
                format!("Tag '{tag}' is invalid"),
            ),
            DistributionError::DigestInvalid(digest) => (
                StatusCode::BAD_REQUEST,
                "DIGEST_INVALID",
                format!("Digest '{digest}' is invalid"),
            ),
            DistributionError::SizeInvalid => (
                StatusCode::BAD_REQUEST,
                "SIZE_INVALID",
                "Provided length did not match Content-Length header".to_string(),
            ),
            DistributionError::RangeInvalid => (
                StatusCode::RANGE_NOT_SATISFIABLE,
                "RANGE_INVALID",
                "Invalid range specified".to_string(),
            ),
            DistributionError::PayloadTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "BLOB_UPLOAD_INVALID",
                "Uploaded blob size exceeds maximum allowed size".to_string(),
            ),
            DistributionError::UploadInvalid(uuid) => (
                StatusCode::BAD_REQUEST,
                "UPLOAD_INVALID",
                format!("Upload '{uuid}' is invalid"),
            ),
            DistributionError::UploadUnknown(uuid) => (
                StatusCode::NOT_FOUND,
                "UPLOAD_UNKNOWN",
                format!("Upload '{uuid}' not found"),
            ),
            DistributionError::UnsupportedMediaType(media_type) => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "UNSUPPORTED",
                format!("Media type '{media_type}' is not supported"),
            ),
            DistributionError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, "UNKNOWN", msg.clone()),
        };

        let error_response = ErrorResponse {
            errors: vec![ErrorDetail {
                code: code.to_string(),
                message,
                detail: None,
            }],
        };

        HttpResponse::build(status).json(error_response)
    }

    fn status_code(&self) -> StatusCode {
        match self {
            DistributionError::NameInvalid(_) => StatusCode::BAD_REQUEST,
            DistributionError::NameUnknown(_) => StatusCode::NOT_FOUND,
            DistributionError::ManifestUnknown(_) => StatusCode::NOT_FOUND,
            DistributionError::ManifestTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            DistributionError::BlobUnknown(_) => StatusCode::NOT_FOUND,
            DistributionError::TagInvalid(_) => StatusCode::BAD_REQUEST,
            DistributionError::DigestInvalid(_) => StatusCode::BAD_REQUEST,
            DistributionError::SizeInvalid => StatusCode::BAD_REQUEST,
            DistributionError::RangeInvalid => StatusCode::RANGE_NOT_SATISFIABLE,
            DistributionError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            DistributionError::UploadInvalid(_) => StatusCode::BAD_REQUEST,
            DistributionError::UploadUnknown(_) => StatusCode::NOT_FOUND,
            DistributionError::UnsupportedMediaType(_) => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            DistributionError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
