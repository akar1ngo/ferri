//! OCI Distribution Specification v1.0.1 implementation
//!
//! This module implements the OCI Distribution API for container registry operations
//! including pulling and pushing container images, manifests, and blobs.

pub mod error;
pub mod names;
pub mod routes;
pub mod storage;

use actix_web::web;
pub use error::*;
pub use names::*;
pub use routes::*;
pub use storage::*;

/// Configures the distribution API routes using service macros
///
/// # Endpoints
///
/// | ID     | Method         | API Endpoint                                                 | Success     | Failure           |
/// | ------ | -------------- | ------------------------------------------------------------ | ----------- | ----------------- |
/// | end-1  | `GET`          | `/v2/`                                                       | `200`       | `404`/`401`       |
/// | end-2  | `GET` / `HEAD` | `/v2/<name>/blobs/<digest>`                                  | `200`       | `404`             |
/// | end-3  | `GET` / `HEAD` | `/v2/<name>/manifests/<reference>`                           | `200`       | `404`             |
/// | end-4a | `POST`         | `/v2/<name>/blobs/uploads/`                                  | `202`       | `404`             |
/// | end-4b | `POST`         | `/v2/<name>/blobs/uploads/?digest=<digest>`                  | `201`/`202` | `404`/`400`       |
/// | end-5  | `PATCH`        | `/v2/<name>/blobs/uploads/<reference>`                       | `202`       | `404`/`416`       |
/// | end-6  | `PUT`          | `/v2/<name>/blobs/uploads/<reference>?digest=<digest>`       | `201`       | `404`/`400`       |
/// | end-7  | `PUT`          | `/v2/<name>/manifests/<reference>`                           | `201`       | `404`             |
/// | end-8a | `GET`          | `/v2/<name>/tags/list`                                       | `200`       | `404`             |
/// | end-8b | `GET`          | `/v2/<name>/tags/list?n=<integer>&last=<integer>`            | `200`       | `404`             |
/// | end-9  | `DELETE`       | `/v2/<name>/manifests/<reference>`                           | `202`       | `404`/`400`/`405` |
/// | end-10 | `DELETE`       | `/v2/<name>/blobs/<digest>`                                  | `202`       | `404`/`405`       |
/// | end-11 | `POST`         | `/v2/<name>/blobs/uploads/?mount=<digest>&from=<other_name>` | `201`       | `404`             |
///
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        // Base API version check
        .service(routes::api_version_check)
        // Pull operations
        .service(routes::get_manifest)
        .service(routes::head_manifest)
        .service(routes::get_blob)
        .service(routes::head_blob)
        // Push operations
        .service(routes::start_blob_upload)
        .service(routes::complete_blob_upload)
        .service(routes::chunked_blob_upload)
        .service(routes::put_manifest)
        // Content discovery
        .service(routes::list_tags)
        .service(routes::list_repositories)
        // Content management
        .service(routes::delete_manifest)
        .service(routes::delete_blob)
        .service(routes::delete_tag);
}

/// Creates the main distribution API service with the provided storage backend
pub fn create_service_with_storage(storage: MemoryStorage) -> impl actix_web::dev::HttpServiceFactory {
    web::scope("")
        .app_data(web::Data::new(storage))
        .configure(configure_routes)
}

/// Configure routes without default storage (for use with external storage setup)
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg
        // Base API version check
        .service(routes::api_version_check)
        // Pull operations
        .service(routes::get_manifest)
        .service(routes::head_manifest)
        .service(routes::get_blob)
        .service(routes::head_blob)
        // Push operations
        .service(routes::start_blob_upload)
        .service(routes::complete_blob_upload)
        .service(routes::chunked_blob_upload)
        .service(routes::put_manifest)
        // Content discovery
        .service(routes::list_tags)
        .service(routes::list_repositories)
        // Content management
        .service(routes::delete_manifest)
        .service(routes::delete_blob)
        .service(routes::delete_tag);
}
