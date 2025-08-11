//! Testing utilities and integration tests for the OCI Distribution Registry
//!
//! This module provides sample data generation and comprehensive integration tests
//! for all registry endpoints. It's designed to make testing easier and more
//! organized than shell scripts.

pub mod sample_data;

use actix_web::http::header::HeaderMap;
use actix_web::{App, test, web};
use serde_json::Value;

use crate::distribution::{MemoryStorage, configure_routes};

/// Test client for making requests to the registry
pub struct RegistryTestClient {
    storage: MemoryStorage,
}

impl RegistryTestClient {
    /// Creates a new test client with empty storage
    pub async fn new() -> Self {
        let storage = MemoryStorage::new();
        Self { storage }
    }

    /// Creates a new test client with sample data pre-loaded
    pub async fn with_sample_data() -> Self {
        let storage = MemoryStorage::new();
        storage.populate_with_sample_data().unwrap();
        Self { storage }
    }

    /// Makes a GET request to the specified path
    pub async fn get(&self, path: &str) -> TestResponse {
        self.request("GET", path, None, vec![]).await
    }

    /// Makes a HEAD request to the specified path
    pub async fn head(&self, path: &str) -> TestResponse {
        self.request("HEAD", path, None, vec![]).await
    }

    /// Makes a POST request to the specified path with optional body
    pub async fn post(&self, path: &str, body: Option<Vec<u8>>) -> TestResponse {
        self.request("POST", path, body, vec![]).await
    }

    /// Makes a PUT request to the specified path with optional body
    pub async fn put(&self, path: &str, body: Option<Vec<u8>>) -> TestResponse {
        self.request("PUT", path, body, vec![]).await
    }

    /// Makes a PATCH request to the specified path with optional body
    pub async fn patch(&self, path: &str, body: Option<Vec<u8>>) -> TestResponse {
        self.request("PATCH", path, body, vec![]).await
    }

    /// Makes a DELETE request to the specified path
    pub async fn delete(&self, path: &str) -> TestResponse {
        self.request("DELETE", path, None, vec![]).await
    }

    /// Makes a request with Range header for partial content
    pub async fn get_with_range(&self, path: &str, range: &str) -> TestResponse {
        self.request("GET", path, None, vec![("Range", range)]).await
    }

    /// Makes a request with custom headers
    pub async fn request_with_headers(
        &self,
        method: &str,
        path: &str,
        headers: Vec<(&str, &str)>,
        body: Option<Vec<u8>>,
    ) -> TestResponse {
        self.request(method, path, body, headers).await
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
        headers: Vec<(&str, &str)>,
    ) -> TestResponse {
        let app = test::init_service(
            App::new()
                .wrap(actix_web::middleware::NormalizePath::trim())
                .app_data(web::Data::new(self.storage.clone()))
                .configure(configure_routes),
        )
        .await;

        let mut req = match method {
            "GET" => test::TestRequest::get(),
            "HEAD" => test::TestRequest::with_uri(path).method(actix_web::http::Method::HEAD),
            "POST" => test::TestRequest::post(),
            "PUT" => test::TestRequest::put(),
            "PATCH" => test::TestRequest::patch(),
            "DELETE" => test::TestRequest::delete(),
            _ => panic!("Unsupported method: {method}"),
        };

        if method != "HEAD" {
            req = req.uri(path);
        }

        for (name, value) in headers {
            req = req.insert_header((name, value));
        }

        if let Some(body_data) = body {
            req = req.set_payload(body_data);
        }

        let request = req.to_request();
        let response = test::call_service(&app, request).await;

        TestResponse::from_response(response).await
    }
}

/// Wrapper for HTTP responses with helper methods for testing
pub struct TestResponse {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl TestResponse {
    async fn from_response(response: actix_web::dev::ServiceResponse) -> Self {
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = test::read_body(response).await.to_vec();

        Self { status, headers, body }
    }

    /// Returns the response body as a UTF-8 string
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    /// Parses the response body as JSON
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }

    /// Returns the response body as raw bytes
    pub fn bytes(&self) -> &[u8] {
        &self.body
    }

    /// Gets a header value as a string
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
    }

    /// Checks if the response has a specific header
    pub fn has_header(&self, name: &str) -> bool {
        self.headers.contains_key(name)
    }

    /// Asserts that the response status matches the expected status
    pub fn assert_status(&self, expected: u16) {
        assert_eq!(
            self.status,
            expected,
            "Expected status {}, got {}. Body: {}",
            expected,
            self.status,
            self.text()
        );
    }

    /// Asserts that the response has a specific header value
    pub fn assert_header(&self, name: &str, expected: &str) {
        let actual = self.header(name).unwrap_or_else(|| {
            panic!("Header '{name}' not found in response");
        });
        assert_eq!(actual, expected, "Header '{name}' mismatch");
    }

    /// Asserts that the response body contains specific text
    pub fn assert_body_contains(&self, text: &str) {
        let body = self.text();
        assert!(
            body.contains(text),
            "Response body does not contain '{text}'. Body: {body}"
        );
    }

    /// Asserts that the response is valid JSON
    pub fn assert_json(&self) -> Value {
        self.json().unwrap_or_else(|e| {
            panic!("Response is not valid JSON: {}. Body: {}", e, self.text());
        })
    }
}

#[cfg(test)]
mod tests {
    use digest::Digest;
    use hmac_sha256::Hash;

    use super::*;

    #[actix_web::test]
    async fn test_api_version_check() {
        let client = RegistryTestClient::new().await;
        let response = client.get("/v2/").await;

        response.assert_status(200);
        response.assert_header("Docker-Distribution-API-Version", "registry/2.0");
        response.assert_header("X-Idol", "AKIRA SUNAZUKA");
    }

    #[actix_web::test]
    async fn test_repository_catalog_empty() {
        let client = RegistryTestClient::new().await;
        let response = client.get("/v2/_catalog").await;

        response.assert_status(200);
        let json = response.assert_json();
        assert_eq!(json["repositories"], serde_json::json!([]));
    }

    #[actix_web::test]
    async fn test_repository_catalog_with_data() {
        let client = RegistryTestClient::with_sample_data().await;
        let response = client.get("/v2/_catalog").await;

        response.assert_status(200);
        let json = response.assert_json();
        let repos = json["repositories"].as_array().unwrap();
        assert!(repos.contains(&serde_json::json!("hello-world")));
        assert!(repos.contains(&serde_json::json!("alpine")));
    }

    #[actix_web::test]
    async fn test_tag_listing() {
        let client = RegistryTestClient::with_sample_data().await;
        let response = client.get("/v2/hello-world/tags/list").await;

        response.assert_status(200);
        let json = response.assert_json();
        assert_eq!(json["name"], "hello-world");
        assert_eq!(json["tags"], serde_json::json!(["latest"]));
    }

    #[actix_web::test]
    async fn test_tag_listing_nonexistent() {
        let client = RegistryTestClient::new().await;
        let response = client.get("/v2/nonexistent/tags/list").await;

        response.assert_status(200);
        let json = response.assert_json();
        assert_eq!(json["name"], "nonexistent");
        assert_eq!(json["tags"], serde_json::json!([]));
    }

    #[actix_web::test]
    async fn test_manifest_operations() {
        let client = RegistryTestClient::with_sample_data().await;

        // Test HEAD manifest
        let response = client.head("/v2/hello-world/manifests/latest").await;
        response.assert_status(200);
        assert!(response.has_header("Docker-Content-Digest"));
        assert!(response.has_header("Content-Length"));

        // Test GET manifest
        let response = client.get("/v2/hello-world/manifests/latest").await;
        response.assert_status(200);
        assert!(response.has_header("Docker-Content-Digest"));
        let json = response.assert_json();
        assert_eq!(json["schemaVersion"], 2);
    }

    #[actix_web::test]
    async fn test_manifest_not_found() {
        let client = RegistryTestClient::new().await;
        let response = client.get("/v2/hello/manifests/latest").await;

        response.assert_status(404);
        let json = response.assert_json();
        assert_eq!(json["errors"][0]["code"], "MANIFEST_UNKNOWN");
    }

    #[actix_web::test]
    async fn test_blob_operations() {
        let client = RegistryTestClient::with_sample_data().await;

        // First get the manifest to extract blob digests
        let manifest_response = client.get("/v2/hello-world/manifests/latest").await;
        let manifest_json = manifest_response.assert_json();
        let config_digest = manifest_json["config"]["digest"].as_str().unwrap();
        let layer_digest = manifest_json["layers"][0]["digest"].as_str().unwrap();

        // Test HEAD blob (config)
        let response = client.head(&format!("/v2/hello-world/blobs/{config_digest}")).await;
        response.assert_status(200);
        assert!(response.has_header("Docker-Content-Digest"));
        assert!(response.has_header("Content-Length"));

        // Test GET blob (config)
        let response = client.get(&format!("/v2/hello-world/blobs/{config_digest}")).await;
        response.assert_status(200);
        assert!(response.has_header("Docker-Content-Digest"));
        let json = response.assert_json();
        assert_eq!(json["architecture"], "amd64");

        // Test GET blob (layer)
        let response = client.get(&format!("/v2/hello-world/blobs/{layer_digest}")).await;
        response.assert_status(200);
        assert!(response.has_header("Docker-Content-Digest"));
        assert!(!response.bytes().is_empty());
    }

    #[actix_web::test]
    async fn test_blob_not_found() {
        let client = RegistryTestClient::new().await;
        let response = client
            .get("/v2/hello/blobs/sha256:0000000000000000000000000000000000000000000000000000000000000000")
            .await;

        response.assert_status(404);
        let json = response.assert_json();
        assert_eq!(json["errors"][0]["code"], "BLOB_UNKNOWN");
    }

    #[actix_web::test]
    async fn test_blob_range_request() {
        let client = RegistryTestClient::with_sample_data().await;

        // Get manifest to extract layer digest
        let manifest_response = client.get("/v2/hello-world/manifests/latest").await;
        let manifest_json = manifest_response.assert_json();
        let layer_digest = manifest_json["layers"][0]["digest"].as_str().unwrap();

        // Test range request
        let response = client
            .get_with_range(&format!("/v2/hello-world/blobs/{layer_digest}"), "bytes=0-49")
            .await;

        response.assert_status(206);
        assert!(response.has_header("Content-Range"));
        assert_eq!(response.bytes().len(), 50);
    }

    #[actix_web::test]
    async fn test_blob_upload_workflow() {
        let client = RegistryTestClient::new().await;
        let test_data = b"test blob data";
        let digest = format!("sha256:{}", hex::encode(Hash::digest(test_data)));

        // Start upload
        let response = client.post("/v2/testrepo/blobs/uploads/", None).await;
        response.assert_status(202);
        let _upload_uuid = response.header("Docker-Upload-UUID").unwrap();
        let location = response.header("Location").unwrap();

        // Upload data
        let response = client
            .put(&format!("{location}?digest={digest}"), Some(test_data.to_vec()))
            .await;
        response.assert_status(201);
        response.assert_header("Docker-Content-Digest", &digest);

        // Verify blob exists
        let response = client.get(&format!("/v2/testrepo/blobs/{digest}")).await;
        response.assert_status(200);
        assert_eq!(response.bytes(), test_data);
    }

    #[actix_web::test]
    async fn test_chunked_upload_workflow() {
        let client = RegistryTestClient::new().await;
        let chunk1 = b"first chunk";
        let chunk2 = b"second chunk";
        let full_data = [chunk1.as_slice(), chunk2.as_slice()].concat();
        let digest = format!("sha256:{}", hex::encode(Hash::digest(&full_data)));

        // Start upload
        let response = client.post("/v2/testrepo/blobs/uploads/", None).await;
        response.assert_status(202);
        let upload_uuid = response.header("Docker-Upload-UUID").unwrap();
        let upload_path = format!("/v2/testrepo/blobs/uploads/{upload_uuid}");

        // Upload first chunk
        let response = client
            .request_with_headers(
                "PATCH",
                &upload_path,
                vec![("Content-Range", "bytes 0-10/*")],
                Some(chunk1.to_vec()),
            )
            .await;
        response.assert_status(202);

        // Upload second chunk and complete
        let response = client
            .request_with_headers(
                "PUT",
                &format!("{upload_path}?digest={digest}"),
                vec![("Content-Range", "bytes 11-22/*")],
                Some(chunk2.to_vec()),
            )
            .await;
        response.assert_status(201);

        // Verify blob
        let response = client.get(&format!("/v2/testrepo/blobs/{digest}")).await;
        response.assert_status(200);
        assert_eq!(response.bytes(), &full_data);
    }

    #[actix_web::test]
    async fn test_manifest_upload() {
        let client = RegistryTestClient::new().await;

        // First upload a config blob
        let config_data = br#"{"architecture":"amd64","os":"linux"}"#;
        let config_digest = format!("sha256:{}", hex::encode(Hash::digest(config_data)));

        let response = client.post("/v2/testrepo/blobs/uploads/", None).await;
        let _upload_uuid = response.header("Docker-Upload-UUID").unwrap();
        let location = response.header("Location").unwrap();

        let response = client
            .put(
                &format!("{location}?digest={config_digest}"),
                Some(config_data.to_vec()),
            )
            .await;
        response.assert_status(201);

        // Create and upload manifest
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": config_data.len()
            },
            "layers": []
        });

        let manifest_data = serde_json::to_vec(&manifest).unwrap();
        let response = client
            .request_with_headers(
                "PUT",
                "/v2/testrepo/manifests/v1.0",
                vec![("Content-Type", "application/vnd.oci.image.manifest.v1+json")],
                Some(manifest_data),
            )
            .await;
        response.assert_status(201);

        // Verify manifest can be retrieved
        let response = client.get("/v2/testrepo/manifests/v1.0").await;
        response.assert_status(200);
        let retrieved_manifest = response.assert_json();
        assert_eq!(retrieved_manifest["schemaVersion"], 2);
    }

    #[actix_web::test]
    async fn test_delete_operations() {
        let client = RegistryTestClient::with_sample_data().await;

        // Get manifest digest
        let response = client.head("/v2/hello-world/manifests/latest").await;
        let manifest_digest = response.header("Docker-Content-Digest").unwrap();

        // Delete manifest
        let response = client
            .delete(&format!("/v2/hello-world/manifests/{manifest_digest}"))
            .await;
        response.assert_status(202);

        // Verify manifest is deleted
        let response = client.get("/v2/hello-world/manifests/latest").await;
        response.assert_status(404);
    }

    #[actix_web::test]
    async fn test_complex_repository_names() {
        let client = RegistryTestClient::new().await;

        // Test the complex repository name case that was problematic with Axum
        let response = client.get("/v2/foo/bar/manifests/manifests/tags").await;
        // Should return 404 (manifest not found) not a routing error
        response.assert_status(404);

        // Test another complex case from the registry tests
        let response = client.get("/v2/foo/bar/manifests/tags/list").await;
        // This should match as a tag list for repo "foo/bar/manifests"
        response.assert_status(200);
        let json = response.assert_json();
        assert_eq!(json["name"], "foo/bar/manifests");
    }

    #[actix_web::test]
    async fn test_registry_v2_compatible_routes() {
        let client = RegistryTestClient::new().await;

        // Test cases derived from the registry:2 test suite
        let test_cases = vec![
            // Basic routes
            ("/v2/foo/manifests/bar", 404),                          // manifest not found
            ("/v2/foo/bar/manifests/tag", 404),                      // manifest not found
            ("/v2/foo/bar/manifests/sha256:abcdef01234567890", 404), // manifest not found
            ("/v2/foo/bar/tags/list", 200),                          // tag list (empty)
            ("/v2/foo/bar/blobs/sha256:abcdef0919234", 404),         // blob not found
            // Complex repository names
            ("/v2/foo/bar/manifests/manifests/tags", 404), // manifest not found
            ("/v2/foo/bar/manifests/tags/list", 200),      // tag list for repo "foo/bar/manifests"
        ];

        for (uri, expected_status) in test_cases {
            let response = client.get(uri).await;
            response.assert_status(expected_status);
        }
    }
}
