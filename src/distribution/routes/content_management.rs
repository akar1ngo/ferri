//! Content management routes for the OCI Distribution API

use actix_web::{HttpResponse, Result, delete, web};

use crate::distribution::{DistributionError, MemoryStorage};

/// Delete manifest - `DELETE /v2/<name>/manifests/<reference>`
///
/// Delete the manifest identified by name and reference. When an image is
/// deleted by tag, all other tags pointing to the same manifest are unaffected.
#[delete("/v2/{name:.*}/manifests/{reference}")]
pub async fn delete_manifest(
    path: web::Path<(String, String)>,
    storage: web::Data<MemoryStorage>,
) -> Result<HttpResponse, DistributionError> {
    let (name, reference) = path.into_inner();
    storage.delete_manifest(&name, &reference)?;

    Ok(HttpResponse::Accepted().finish())
}

/// Delete blob - `DELETE /v2/<name>/blobs/<digest>`
///
/// Delete the blob identified by name and digest.
#[delete("/v2/{name:.*}/blobs/{digest}")]
pub async fn delete_blob(
    path: web::Path<(String, String)>,
    storage: web::Data<MemoryStorage>,
) -> Result<HttpResponse, DistributionError> {
    let (_, digest) = path.into_inner();
    storage.delete_blob(&digest)?;

    Ok(HttpResponse::Accepted().finish())
}

/// Delete tag - `DELETE /v2/<name>/tags/<reference>`
///
/// Delete the tag identified by name and reference.
#[delete("/v2/{name:.*}/tags/{reference}")]
pub async fn delete_tag(
    path: web::Path<(String, String)>,
    storage: web::Data<MemoryStorage>,
) -> Result<HttpResponse, DistributionError> {
    let (name, reference) = path.into_inner();
    storage.delete_manifest(&name, &reference)?;

    Ok(HttpResponse::Accepted().finish())
}
