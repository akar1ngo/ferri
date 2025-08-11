//! Content discovery routes for the OCI Distribution API

use actix_web::{HttpResponse, Result, get, web};
use serde::{Deserialize, Serialize};

use crate::distribution::{DistributionError, MemoryStorage};

#[derive(Deserialize)]
pub struct ListTagsQuery {
    /// number of entries to return
    n: Option<u32>,
    /// last tag value for pagination
    last: Option<String>,
}

#[derive(Serialize)]
pub struct TagsResponse {
    pub name: String,
    pub tags: Vec<String>,
}

/// List tags - `GET /v2/<name>/tags/list`
///
/// Fetch the tags under the repository identified by name.
#[get("/v2/{name:.*}/tags/list")]
pub async fn list_tags(
    path: web::Path<String>,
    query: web::Query<ListTagsQuery>,
    storage: web::Data<MemoryStorage>,
) -> Result<HttpResponse, DistributionError> {
    let name = path.into_inner();
    let mut tags = storage.list_tags(&name)?;
    paginate(&mut tags, query.last.as_ref(), query.n);

    let response = TagsResponse { name, tags };

    Ok(HttpResponse::Ok().json(response))
}

#[derive(Deserialize)]
pub struct CatalogQuery {
    /// number of entries to return
    n: Option<u32>,
    /// last repository name for pagination
    last: Option<String>,
}

#[derive(Serialize)]
pub struct CatalogResponse {
    pub repositories: Vec<String>,
}

/// List repositories - `GET /v2/_catalog`
///
/// List a set of available repositories in the local registry cluster.
#[get("/v2/_catalog")]
pub async fn list_repositories(
    query: web::Query<CatalogQuery>,
    storage: web::Data<MemoryStorage>,
) -> Result<HttpResponse, DistributionError> {
    let mut repositories = storage.list_repositories()?;
    paginate(&mut repositories, query.last.as_ref(), query.n);

    let response = CatalogResponse { repositories };

    Ok(HttpResponse::Ok().json(response))
}

pub fn paginate<T: PartialEq>(items: &mut Vec<T>, last: Option<&T>, n: Option<u32>) {
    // If `last` is provided and found, drop everything up to and including it.
    if let Some(last) = last {
        if let Some(pos) = items.iter().position(|item| item == last) {
            items.drain(..=pos);
        }
    }

    // Apply limit `n` if provided.
    if let Some(n) = n {
        items.truncate(n as usize);
    }
}
