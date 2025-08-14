//! Pull operation routes for the OCI Distribution API

use actix_web::http::header::{self, Header};
use actix_web::{HttpRequest, HttpResponse, Result, get, head, web};
use digest::Digest;
use hmac_sha256::Hash;

use crate::distribution::{DistributionError, StorageService};

/// Get manifest - `GET /v2/<name>/manifests/<reference>`
///
/// Retrieve the manifest identified by name and reference where reference
/// can be a tag or digest.
#[get("/v2/{name:.*}/manifests/{reference}")]
pub async fn get_manifest(
    path: web::Path<(String, String)>,
    storage: web::Data<StorageService>,
) -> Result<HttpResponse, DistributionError> {
    let (name, reference) = path.into_inner();

    let manifest_entry = storage.get_manifest(&name, &reference).await?;
    let digest = format!("sha256:{}", hex::encode(Hash::digest(&manifest_entry.data)));

    Ok(HttpResponse::Ok()
        .insert_header(("Content-Type", manifest_entry.content_type))
        .insert_header(("Docker-Content-Digest", digest))
        .insert_header(("Content-Length", manifest_entry.data.len().to_string()))
        .body(manifest_entry.data))
}

/// Check manifest exists - `HEAD /v2/<name>/manifests/<reference>`
///
/// Same as GET manifest but only returns headers, used to check if a
/// manifest exists without downloading it.
#[head("/v2/{name:.*}/manifests/{reference}")]
pub async fn head_manifest(
    path: web::Path<(String, String)>,
    storage: web::Data<StorageService>,
) -> Result<HttpResponse, DistributionError> {
    let (name, reference) = path.into_inner();

    if !storage.manifest_exists(&name, &reference).await? {
        return Err(DistributionError::ManifestUnknown(reference));
    }

    let manifest_entry = storage.get_manifest(&name, &reference).await?;
    let digest = format!("sha256:{}", hex::encode(Hash::digest(&manifest_entry.data)));

    Ok(HttpResponse::Ok()
        .insert_header(("Content-Type", manifest_entry.content_type))
        .insert_header(("Docker-Content-Digest", digest))
        .insert_header(("Content-Length", manifest_entry.data.len().to_string()))
        .finish())
}

/// Get blob - `GET /v2/<name>/blobs/<digest>`
///
/// Retrieve the blob from the registry identified by digest.
#[get("/v2/{name:.*}/blobs/{digest}")]
pub async fn get_blob(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    storage: web::Data<StorageService>,
) -> Result<HttpResponse, DistributionError> {
    let (_, digest) = path.into_inner();
    let blob_data = storage.get_blob(&digest).await?;

    if req.headers().contains_key(header::RANGE) {
        match header::Range::parse(&req) {
            Ok(header::Range::Bytes(byte_specs)) => {
                // For now, we do not support multipart ranges.
                if byte_specs.len() > 1 {
                    return Err(DistributionError::RangeInvalid);
                }

                let byte_spec = &byte_specs[0];
                let total_len = blob_data.len() as u64;
                if let Some((start, end)) = byte_spec.to_satisfiable_range(total_len) {
                    let start = start as usize;
                    let end = end as usize;
                    // Ranges are zero-indexed and inclusive
                    let partial_data = blob_data[start..=end].to_vec();

                    return Ok(HttpResponse::PartialContent()
                        .insert_header(("Content-Type", "application/octet-stream"))
                        .insert_header(("Content-Length", partial_data.len().to_string()))
                        .insert_header(("Content-Range", format!("bytes {start}-{end}/{total_len}")))
                        .insert_header(("Docker-Content-Digest", digest))
                        .body(partial_data));
                }
            }

            _ => return Err(DistributionError::RangeInvalid),
        };
    }

    // Return full blob
    Ok(HttpResponse::Ok()
        .insert_header(("Content-Type", "application/octet-stream"))
        .insert_header(("Content-Length", blob_data.len().to_string()))
        .insert_header(("Docker-Content-Digest", digest))
        .body(blob_data))
}

/// Check blob exists - `HEAD /v2/<name>/blobs/<digest>`
///
/// Same as GET blob but only returns headers, used to check if a
/// blob exists without downloading it.
#[head("/v2/{name:.*}/blobs/{digest}")]
pub async fn head_blob(
    path: web::Path<(String, String)>,
    storage: web::Data<StorageService>,
) -> Result<HttpResponse, DistributionError> {
    let (_, digest) = path.into_inner();

    if !storage.blob_exists(&digest).await? {
        return Err(DistributionError::BlobUnknown(digest));
    }

    let blob_data = storage.get_blob(&digest).await?;

    Ok(HttpResponse::Ok()
        .insert_header(("Content-Type", "application/octet-stream"))
        .insert_header(("Content-Length", blob_data.len().to_string()))
        .insert_header(("Docker-Content-Digest", digest))
        .finish())
}
