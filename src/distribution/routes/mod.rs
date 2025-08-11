//! Route module for the OCI Distribution API
//!
//! This module organizes the distribution routes into logical groups:
//!
//! - [`base`] - API version check and base functionality
//! - [`pull`] - Pull operations (`GET`/`HEAD` manifests and blobs)
//! - [`push`] - Push operations (`POST`/`PATCH`/`PUT` blob uploads and manifest push)
//! - [`content_discovery`] - Content discovery (tag listing, repository catalog)
//! - [`content_management`] - Content management (`DELETE` operations)
//!

pub mod base;
pub mod content_discovery;
pub mod content_management;
pub mod pull;
pub mod push;

#[cfg(test)]
pub mod router_tests;

pub use base::*;
pub use content_discovery::*;
pub use content_management::*;
pub use pull::*;
pub use push::*;
