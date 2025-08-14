use actix_web::middleware::Logger;
use actix_web::{App, HttpServer, middleware, web};
use ferri::distribution::{self, DistributionError, StorageService};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::new(r#"%a "%r" %s %b %T"#))
            .wrap(
                middleware::DefaultHeaders::new()
                    .add(("Docker-Distribution-API-Version", "registry/2.0"))
                    .add(("Cache-Control", "no-cache")),
            )
            .wrap(middleware::NormalizePath::trim())
            .app_data(web::PayloadConfig::new(1 << 30)) // 1 GB blob limit
            .app_data(
                web::JsonConfig::default()
                    .limit(1 << 20) // 1 MB JSON limit
                    .error_handler(|err, _| {
                        log::warn!("JSON payload error: {err}");
                        actix_web::error::InternalError::from_response(
                            err,
                            actix_web::HttpResponse::from_error(DistributionError::ManifestTooLarge),
                        )
                        .into()
                    }),
            )
            .app_data(web::Data::new(StorageService::new_memory()))
            .configure(distribution::configure_routes)
    })
    .client_request_timeout(std::time::Duration::from_secs(600))
    .client_disconnect_timeout(std::time::Duration::from_secs(60))
    .keep_alive(std::time::Duration::from_secs(120))
    .server_hostname("localhost")
    .workers(1)
    .bind("0.0.0.0:5000")?
    .run()
    .await
}
