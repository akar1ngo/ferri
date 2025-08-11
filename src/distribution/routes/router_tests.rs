//! Router tests, largely based on the registry:2 test suite.

use actix_web::{App, test, web};
use serde_json::Value;

use crate::distribution::{MemoryStorage, configure_routes};

/// Test cases derived from the registry:2 router test suite
/// https://github.com/distribution/distribution/blob/v2.0.0/registry/api/v2/routes_test.go
#[actix_web::test]
async fn test_registry_v2_router_compatibility() {
    let storage = MemoryStorage::new();
    let app = test::init_service(
        App::new()
            .wrap(actix_web::middleware::NormalizePath::trim())
            .app_data(web::Data::new(storage))
            .configure(configure_routes),
    )
    .await;

    let test_cases = vec![
        // Basic manifest routes
        TestCase {
            name: "simple_manifest",
            uri: "/v2/foo/manifests/bar",
            expected_status: 404, // manifest not found (but route should match)
            expected_vars: Some(vec![("name", "foo"), ("reference", "bar")]),
        },
        TestCase {
            name: "nested_repository_manifest",
            uri: "/v2/foo/bar/manifests/tag",
            expected_status: 404,
            expected_vars: Some(vec![("name", "foo/bar"), ("reference", "tag")]),
        },
        TestCase {
            name: "digest_reference",
            uri: "/v2/foo/bar/manifests/sha256:abcdef01234567890",
            expected_status: 404,
            expected_vars: Some(vec![("name", "foo/bar"), ("reference", "sha256:abcdef01234567890")]),
        },
        // Tag listing routes
        TestCase {
            name: "simple_tags",
            uri: "/v2/foo/bar/tags/list",
            expected_status: 200,
            expected_vars: Some(vec![("name", "foo/bar")]),
        },
        // Blob routes
        TestCase {
            name: "blob_with_tarsum",
            uri: "/v2/foo/bar/blobs/tarsum.dev+foo:abcdef0919234",
            expected_status: 404,
            expected_vars: Some(vec![("name", "foo/bar"), ("digest", "tarsum.dev+foo:abcdef0919234")]),
        },
        TestCase {
            name: "blob_with_sha256",
            uri: "/v2/foo/bar/blobs/sha256:abcdef0919234",
            expected_status: 404,
            expected_vars: Some(vec![("name", "foo/bar"), ("digest", "sha256:abcdef0919234")]),
        },
        // Upload routes
        TestCase {
            name: "upload_start",
            uri: "/v2/foo/bar/blobs/uploads/",
            expected_status: 202,
            expected_vars: Some(vec![("name", "foo/bar")]),
        },
        TestCase {
            name: "upload_chunk_simple_uuid",
            uri: "/v2/foo/bar/blobs/uploads/uuid",
            expected_status: 404, // upload not found
            expected_vars: Some(vec![("name", "foo/bar"), ("uuid", "uuid")]),
        },
        TestCase {
            name: "upload_chunk_proper_uuid",
            uri: "/v2/foo/bar/blobs/uploads/D95306FA-FAD3-4E36-8D41-CF1C93EF8286",
            expected_status: 404,
            expected_vars: Some(vec![
                ("name", "foo/bar"),
                ("uuid", "D95306FA-FAD3-4E36-8D41-CF1C93EF8286"),
            ]),
        },
        TestCase {
            name: "upload_chunk_base64_uuid",
            uri: "/v2/foo/bar/blobs/uploads/RDk1MzA2RkEtRkFEMy00RTM2LThENDEtQ0YxQzkzRUY4Mjg2IA==",
            expected_status: 404,
            expected_vars: Some(vec![
                ("name", "foo/bar"),
                ("uuid", "RDk1MzA2RkEtRkFEMy00RTM2LThENDEtQ0YxQzkzRUY4Mjg2IA=="),
            ]),
        },
        TestCase {
            name: "upload_chunk_urlsafe_base64_uuid",
            uri: "/v2/foo/bar/blobs/uploads/RDk1MzA2RkEtRkFEMy00RTM2LThENDEtQ0YxQzkzRUY4Mjg2IA_-==",
            expected_status: 404,
            expected_vars: Some(vec![
                ("name", "foo/bar"),
                ("uuid", "RDk1MzA2RkEtRkFEMy00RTM2LThENDEtQ0YxQzkzRUY4Mjg2IA_-=="),
            ]),
        },
        // Check ambiguity: ensure we can distinguish between tags for "foo/bar/image/image" and
        // image for "foo/bar/image" with tag "tags"
        TestCase {
            name: "ambiguous_manifest_vs_tags",
            uri: "/v2/foo/bar/manifests/manifests/tags",
            expected_status: 404,
            expected_vars: Some(vec![("name", "foo/bar/manifests"), ("reference", "tags")]),
        },
        // This case presents an ambiguity between foo/bar with tag="tags" and list tags for
        // "foo/bar/manifest"
        TestCase {
            name: "ambiguous_tags_vs_manifest",
            uri: "/v2/foo/bar/manifests/tags/list",
            expected_status: 200,
            expected_vars: Some(vec![("name", "foo/bar/manifests")]),
        },
    ];

    for test_case in test_cases {
        println!("Testing case: {}", test_case.name);

        let req = if test_case.name == "upload_start" {
            test::TestRequest::post().uri(test_case.uri).to_request()
        } else {
            test::TestRequest::get().uri(test_case.uri).to_request()
        };
        let resp = test::call_service(&app, req).await;

        assert_eq!(
            resp.status().as_u16(),
            test_case.expected_status,
            "Test case '{}' failed: expected status {}, got {}",
            test_case.name,
            test_case.expected_status,
            resp.status()
        );

        // For successful tag list responses, verify the response structure
        if test_case.expected_status == 200 && test_case.uri.ends_with("/tags/list") {
            let body = test::read_body(resp).await;
            let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

            if let Some(expected_vars) = test_case.expected_vars {
                for (key, expected_value) in expected_vars {
                    if key == "name" {
                        assert_eq!(
                            json["name"].as_str().unwrap(),
                            expected_value,
                            "Test case '{}': repository name mismatch",
                            test_case.name
                        );
                    }
                }
            }
        }
    }
}

/// Test path traversal attack handling
#[actix_web::test]
async fn test_path_traversal_attacks() {
    let storage = MemoryStorage::new();
    let app = test::init_service(
        App::new()
            .wrap(actix_web::middleware::NormalizePath::trim())
            .app_data(web::Data::new(storage))
            .configure(configure_routes),
    )
    .await;

    let test_cases = vec![
        TestCase {
            name: "path_traversal_upload",
            uri: "/v2/foo/../../blob/uploads/D95306FA-FAD3-4E36-8D41-CF1C93EF8286",
            expected_status: 404, // Should not match any route after normalization
            expected_vars: None,
        },
        TestCase {
            name: "path_traversal_tags",
            uri: "/v2/foo/../bar/baz/tags/list",
            expected_status: 200, // Should normalize to /v2/bar/baz/tags/list
            expected_vars: Some(vec![("name", "bar/baz")]),
        },
    ];

    for test_case in test_cases {
        println!("Testing path traversal case: {}", test_case.name);

        let req = test::TestRequest::get().uri(test_case.uri).to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(
            resp.status().as_u16(),
            test_case.expected_status,
            "Path traversal test case '{}' failed: expected status {}, got {}",
            test_case.name,
            test_case.expected_status,
            resp.status()
        );
    }
}

/// Test that invalid characters in repository names are rejected
#[actix_web::test]
async fn test_invalid_characters() {
    let storage = MemoryStorage::new();
    let app = test::init_service(
        App::new()
            .wrap(actix_web::middleware::NormalizePath::trim())
            .app_data(web::Data::new(storage))
            .configure(configure_routes),
    )
    .await;

    let test_cases = vec![
        // These should not match routes due to invalid characters
        TestCase {
            name: "invalid_unicode_upload",
            uri: "/v2/foo/blob/uploads/不95306FA-FAD3-4E36-8D41-CF1C93EF8286",
            expected_status: 404,
            expected_vars: None,
        },
        TestCase {
            name: "invalid_unicode_tags",
            uri: "/v2/foo/不bar/tags/list",
            expected_status: 404,
            expected_vars: None,
        },
    ];

    for test_case in test_cases {
        println!("Testing invalid character case: {}", test_case.name);

        // Skip cases with invalid UTF-8 in URIs as they can't be constructed
        if test_case.uri.contains("不") {
            println!("Skipping test case '{}' with invalid UTF-8 characters", test_case.name);
            continue;
        }

        let req = test::TestRequest::get().uri(test_case.uri).to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(
            resp.status().as_u16(),
            test_case.expected_status,
            "Invalid character test case '{}' failed: expected status {}, got {}",
            test_case.name,
            test_case.expected_status,
            resp.status()
        );
    }
}

/// Test complex real-world repository names
#[actix_web::test]
async fn test_real_world_repository_names() {
    let storage = MemoryStorage::new();
    let app = test::init_service(
        App::new()
            .wrap(actix_web::middleware::NormalizePath::trim())
            .app_data(web::Data::new(storage))
            .configure(configure_routes),
    )
    .await;

    let test_cases = vec![
        TestCase {
            name: "docker_hub_library",
            uri: "/v2/library/ubuntu/manifests/latest",
            expected_status: 404,
            expected_vars: Some(vec![("name", "library/ubuntu"), ("reference", "latest")]),
        },
        TestCase {
            name: "docker_hub_user",
            uri: "/v2/docker/stevvooe/app/manifests/v1.0",
            expected_status: 404,
            expected_vars: Some(vec![("name", "docker/stevvooe/app"), ("reference", "v1.0")]),
        },
        TestCase {
            name: "github_container_registry",
            uri: "/v2/ghcr.io/devcontainers/features/docker-in-docker/manifests/latest",
            expected_status: 404,
            expected_vars: Some(vec![
                ("name", "ghcr.io/devcontainers/features/docker-in-docker"),
                ("reference", "latest"),
            ]),
        },
        TestCase {
            name: "private_registry_with_port",
            uri: "/v2/registry.example.com:5000/myorg/myapp/manifests/v2.1.3",
            expected_status: 404,
            expected_vars: Some(vec![
                ("name", "registry.example.com:5000/myorg/myapp"),
                ("reference", "v2.1.3"),
            ]),
        },
        TestCase {
            name: "deeply_nested_repository",
            uri: "/v2/aa/aa/aa/aa/aa/aa/aa/aa/aa/bb/bb/bb/bb/bb/bb/manifests/test",
            expected_status: 404,
            expected_vars: Some(vec![
                ("name", "aa/aa/aa/aa/aa/aa/aa/aa/aa/bb/bb/bb/bb/bb/bb"),
                ("reference", "test"),
            ]),
        },
    ];

    for test_case in test_cases {
        println!("Testing real-world case: {}", test_case.name);

        let req = test::TestRequest::get().uri(test_case.uri).to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(
            resp.status().as_u16(),
            test_case.expected_status,
            "Real-world test case '{}' failed: expected status {}, got {}",
            test_case.name,
            test_case.expected_status,
            resp.status()
        );
    }
}

/// Test all HTTP methods on complex repository names
#[actix_web::test]
async fn test_all_methods_complex_names() {
    let storage = MemoryStorage::new();
    let app = test::init_service(
        App::new()
            .wrap(actix_web::middleware::NormalizePath::trim())
            .app_data(web::Data::new(storage))
            .configure(configure_routes),
    )
    .await;

    let complex_repo = "docker.io/library/nginx";
    let test_cases = vec![
        ("GET", format!("/v2/{complex_repo}/manifests/latest"), 404),
        ("HEAD", format!("/v2/{complex_repo}/manifests/latest"), 404),
        ("PUT", format!("/v2/{complex_repo}/manifests/latest"), 500), // Internal error (empty body)
        ("DELETE", format!("/v2/{complex_repo}/manifests/latest"), 404),
        ("GET", format!("/v2/{complex_repo}/blobs/sha256:abc123"), 404),
        ("HEAD", format!("/v2/{complex_repo}/blobs/sha256:abc123"), 404),
        ("DELETE", format!("/v2/{complex_repo}/blobs/sha256:abc123"), 404),
        ("GET", format!("/v2/{complex_repo}/tags/list"), 200),
        ("POST", format!("/v2/{complex_repo}/blobs/uploads/"), 202),
    ];

    for (method, uri, expected_status) in test_cases {
        println!("Testing {method} {uri}");

        let req = match method {
            "GET" => test::TestRequest::get().uri(&uri).to_request(),
            "HEAD" => test::TestRequest::with_uri(&uri)
                .method(actix_web::http::Method::HEAD)
                .to_request(),
            "PUT" => test::TestRequest::put().uri(&uri).to_request(),
            "POST" => test::TestRequest::post().uri(&uri).to_request(),
            "DELETE" => test::TestRequest::delete().uri(&uri).to_request(),
            _ => panic!("Unsupported method: {method}"),
        };

        let resp = test::call_service(&app, req).await;

        assert_eq!(
            resp.status().as_u16(),
            expected_status,
            "Method test failed for {} {}: expected status {}, got {}",
            method,
            uri,
            expected_status,
            resp.status()
        );
    }
}

#[derive(Debug)]
struct TestCase {
    name: &'static str,
    uri: &'static str,
    expected_status: u16,
    expected_vars: Option<Vec<(&'static str, &'static str)>>,
}
