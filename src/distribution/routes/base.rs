//! Base API routes for the OCI Distribution API

use actix_web::{HttpResponse, get};

/// API version check endpoint - `GET /v2/`
///
/// This endpoint serves as a version check for the Distribution API. Clients
/// should be able to make a GET request to this endpoint to determine if the
/// registry supports the v2 API and to check for authentication.
#[get("/v2")]
pub async fn api_version_check() -> HttpResponse {
    HttpResponse::Ok()
        .insert_header(("Docker-Distribution-API-Version", "registry/2.0"))
        .insert_header(("X-Idol", "AKIRA SUNAZUKA"))
        .finish()
}
