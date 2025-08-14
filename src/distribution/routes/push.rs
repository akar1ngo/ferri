//! Push operation routes for the OCI Distribution API

use std::collections::HashMap;

use actix_web::{HttpRequest, HttpResponse, Result, patch, post, put, web};
use serde::Deserialize;

use crate::distribution::{DistributionError, StorageService};

const MAX_BLOB_SIZE: usize = 1 << 30; // 1GB
const MAX_MANIFEST_SIZE: usize = 4 << 20; // 4MB

#[derive(Deserialize)]
pub struct UploadQuery {
    mount: Option<String>,
    from: Option<String>,
}

/// Start blob upload - `POST /v2/<name>/blobs/uploads/`
///
/// Initiate a resumable blob upload. Optionally mount a blob from another
/// repository if mount and from parameters are provided.
#[post("/v2/{name:.*}/blobs/uploads")]
pub async fn start_blob_upload(
    path: web::Path<String>,
    query: web::Query<UploadQuery>,
    storage: web::Data<StorageService>,
) -> Result<HttpResponse, DistributionError> {
    let name = path.into_inner();

    // Check if this is a mount request
    if let (Some(digest), Some(from_repo)) = (query.mount.clone(), query.from.clone()) {
        // Attempt to mount blob from another repository
        if storage.mount_blob(&from_repo, &name, &digest).await? {
            // Mount successful
            let blob_url = format!("/v2/{name}/blobs/{digest}");
            return Ok(HttpResponse::Created()
                .insert_header(("Location", blob_url))
                .insert_header(("Docker-Content-Digest", digest))
                .finish());
        }
        // Mount failed, fall through to start upload session
    }

    // Start new upload session
    let session = storage.start_upload(&name).await?;
    let upload_url = format!("/v2/{}/blobs/uploads/{}", name, session.uuid);

    Ok(HttpResponse::Accepted()
        .insert_header(("Location", upload_url))
        .insert_header(("Docker-Upload-UUID", session.uuid))
        .insert_header(("Range", "0-0"))
        .finish())
}

/// Complete blob upload - `PUT /v2/<name>/blobs/uploads/<uuid>`
///
/// Complete the upload specified by uuid, optionally appending the body
/// as the final chunk.
#[put("/v2/{name:.*}/blobs/uploads/{uuid}")]
pub async fn complete_blob_upload(
    path: web::Path<(String, String)>,
    query: web::Query<HashMap<String, String>>,
    storage: web::Data<StorageService>,
    req: HttpRequest,
    body: web::Bytes,
) -> Result<HttpResponse, DistributionError> {
    let (name, uuid) = path.into_inner();

    // Get the digest from query parameters
    let digest = query
        .get("digest")
        .ok_or_else(|| DistributionError::DigestInvalid("Missing digest parameter".to_string()))?;

    // Get the upload session
    let mut session = storage.get_upload(&uuid).await?;

    // If there's a body, append it as the final chunk
    if !body.is_empty() {
        // Check payload size before processing
        if body.len() > MAX_BLOB_SIZE {
            return Err(DistributionError::PayloadTooLarge);
        }

        // Check total size after appending
        if session.data.len() + body.len() > MAX_BLOB_SIZE {
            return Err(DistributionError::PayloadTooLarge);
        }

        // Validate Content-Range if provided
        if let Some(range_header) = req.headers().get("Content-Range") {
            let range_str = range_header.to_str().map_err(|_| DistributionError::RangeInvalid)?;

            let expected_start = session.data.len();
            if !validate_content_range(range_str, expected_start) {
                return Err(DistributionError::RangeInvalid);
            }
        }

        session.data.extend_from_slice(&body);
        // Update the session in storage with the new data
        storage.update_upload(session).await?;
    }

    // Complete the upload
    storage.complete_upload(&uuid, digest).await?;

    // Return success response
    let blob_url = format!("/v2/{name}/blobs/{digest}");
    Ok(HttpResponse::Created()
        .insert_header(("Location", blob_url))
        .insert_header(("Docker-Content-Digest", digest.as_str()))
        .finish())
}

/// Chunked blob upload - `PATCH /v2/<name>/blobs/uploads/<uuid>`
///
/// Upload a chunk of data for the upload specified by uuid.
#[patch("/v2/{name:.*}/blobs/uploads/{uuid}")]
pub async fn chunked_blob_upload(
    path: web::Path<(String, String)>,
    storage: web::Data<StorageService>,
    req: HttpRequest,
    body: web::Bytes,
) -> Result<HttpResponse, DistributionError> {
    let (name, uuid) = path.into_inner();

    // Get the upload session
    let mut session = storage.get_upload(&uuid).await?;

    // Check payload size before processing
    if body.len() > MAX_BLOB_SIZE {
        return Err(DistributionError::PayloadTooLarge);
    }

    // Check total size after appending
    if session.data.len() + body.len() > MAX_BLOB_SIZE {
        return Err(DistributionError::PayloadTooLarge);
    }

    // Validate Content-Range header
    if let Some(range_header) = req.headers().get("Content-Range") {
        let range_str = range_header.to_str().map_err(|_| DistributionError::RangeInvalid)?;

        let expected_start = session.data.len();
        if !validate_content_range(range_str, expected_start) {
            return Err(DistributionError::RangeInvalid);
        }
    }

    // Append the chunk data
    session.data.extend_from_slice(&body);
    session.offset = session.data.len();

    // Store the offset for response before moving session
    let current_offset = session.offset;

    // Update the session
    storage.update_upload(session).await?;

    // Return upload status
    let upload_url = format!("/v2/{name}/blobs/uploads/{uuid}");
    let range = format!("0-{}", current_offset.saturating_sub(1));

    Ok(HttpResponse::Accepted()
        .insert_header(("Location", upload_url))
        .insert_header(("Range", range))
        .insert_header(("Docker-Upload-UUID", uuid))
        .finish())
}

/// Put manifest - `PUT /v2/<name>/manifests/<reference>`
///
/// Put the manifest identified by name and reference where reference
/// can be a tag or digest.
#[put("/v2/{name:.*}/manifests/{reference}")]
pub async fn put_manifest(
    path: web::Path<(String, String)>,
    storage: web::Data<StorageService>,
    req: HttpRequest,
    body: web::Bytes,
) -> Result<HttpResponse, DistributionError> {
    let (name, reference) = path.into_inner();

    // Check manifest size
    if body.len() > MAX_MANIFEST_SIZE {
        return Err(DistributionError::PayloadTooLarge);
    }

    // Validate Content-Type header
    let content_type = req
        .headers()
        .get("Content-Type")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("application/vnd.oci.image.manifest.v1+json");

    // Basic validation of content type
    if !is_valid_manifest_content_type(content_type) {
        return Err(DistributionError::UnsupportedMediaType(content_type.to_string()));
    }

    // Parse and validate the manifest
    let manifest_data = body.to_vec();
    validate_manifest_json(&manifest_data)?;

    // Store the manifest
    let digest = storage
        .put_manifest(&name, &reference, manifest_data, content_type.to_string())
        .await?;

    // Return success response
    let manifest_url = format!("/v2/{name}/manifests/{reference}");
    Ok(HttpResponse::Created()
        .insert_header(("Location", manifest_url))
        .insert_header(("Docker-Content-Digest", digest))
        .finish())
}

/// Validates Content-Range header format and position
fn validate_content_range(range_str: &str, expected_start: usize) -> bool {
    // Expected format: "bytes start-end/*" or "bytes start-end/total"
    if let Some(bytes_part) = range_str.strip_prefix("bytes ")
        && let Some((range_part, _)) = bytes_part.split_once('/')
        && let Some((start_str, _)) = range_part.split_once('-')
        && let Ok(start) = start_str.parse::<usize>()
    {
        return start == expected_start;
    }
    false
}

/// Validates that the content type is acceptable for manifests
fn is_valid_manifest_content_type(content_type: &str) -> bool {
    matches!(
        content_type,
        "application/vnd.oci.image.manifest.v1+json"
            | "application/vnd.oci.image.index.v1+json"
            | "application/vnd.docker.distribution.manifest.v2+json"
            | "application/vnd.docker.distribution.manifest.list.v2+json"
    )
}

/// Basic validation that the manifest is valid JSON
fn validate_manifest_json(data: &[u8]) -> Result<(), DistributionError> {
    serde_json::from_slice::<serde_json::Value>(data)
        .map_err(|e| DistributionError::InternalError(format!("Invalid JSON manifest: {e}")))?;
    Ok(())
}
