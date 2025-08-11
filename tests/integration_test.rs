use actix_web::{App, test, web};
use ferri::distribution::*;

#[actix_web::test]
async fn test_api_version_check() {
    let storage = MemoryStorage::new();
    let app = test::init_service(
        App::new()
            .wrap(actix_web::middleware::NormalizePath::trim())
            .app_data(web::Data::new(storage))
            .configure(configure_routes),
    )
    .await;

    let req = test::TestRequest::get().uri("/v2/").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 200);

    let headers = resp.headers();
    assert_eq!(headers.get("Docker-Distribution-API-Version").unwrap(), "registry/2.0");
}

#[actix_web::test]
async fn test_manifest_not_found() {
    let storage = MemoryStorage::new();
    let app = test::init_service(
        App::new()
            .wrap(actix_web::middleware::NormalizePath::trim())
            .app_data(web::Data::new(storage))
            .configure(configure_routes),
    )
    .await;

    let req = test::TestRequest::get().uri("/v2/hello/manifests/latest").to_request();
    let resp: ErrorResponse = test::call_and_read_body_json(&app, req).await;
    let error = resp.errors.first().unwrap();

    assert_eq!(error.code, "MANIFEST_UNKNOWN")
}

#[actix_web::test]
async fn test_blob_not_found() {
    let storage = MemoryStorage::new();
    let app = test::init_service(
        App::new()
            .wrap(actix_web::middleware::NormalizePath::trim())
            .app_data(web::Data::new(storage))
            .configure(configure_routes),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/v2/hello/blobs/sha256:abc123")
        .to_request();
    let resp: ErrorResponse = test::call_and_read_body_json(&app, req).await;
    let error = resp.errors.first().unwrap();

    assert_eq!(error.code, "BLOB_UNKNOWN")
}

#[actix_web::test]
async fn test_catalog_empty() {
    let storage = MemoryStorage::new();
    let app = test::init_service(
        App::new()
            .wrap(actix_web::middleware::NormalizePath::trim())
            .app_data(web::Data::new(storage))
            .configure(configure_routes),
    )
    .await;

    let req = test::TestRequest::get().uri("/v2/_catalog").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 200);
}

#[actix_web::test]
async fn test_complex_repository_names() {
    let storage = MemoryStorage::new();
    let app = test::init_service(
        App::new()
            .wrap(actix_web::middleware::NormalizePath::trim())
            .app_data(web::Data::new(storage))
            .configure(configure_routes),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/v2/hoge/fuga/piyo/manifests/tags")
        .to_request();
    let resp: ErrorResponse = test::call_and_read_body_json(&app, req).await;
    let error = resp.errors.first().unwrap();

    assert_eq!(error.code, "MANIFEST_UNKNOWN")
}
