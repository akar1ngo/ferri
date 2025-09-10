use std::io;
use std::path::PathBuf;
use std::time::Duration;

use actix_web::middleware::Logger;
use actix_web::{App, HttpServer, middleware, web};
use clap::{Parser, ValueEnum};
use ferri::distribution::{self, DistributionError, StorageService, UploadLimits};

#[derive(Parser)]
struct Args {
    /// Storage backend
    #[arg(long, default_value = "mem")]
    storage: StorageType,

    /// Data directory for file storage
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Maximum blob size in bytes
    #[arg(long, default_value_t = 1 << 30)]
    max_blob_size: usize,

    /// Maximum manifest size in bytes
    #[arg(long, default_value_t = 4 << 20)]
    max_manifest_size: usize,

    /// Client request timeout in seconds
    #[arg(long, default_value = "600")]
    request_timeout: u64,

    /// Client disconnect timeout in seconds
    #[arg(long, default_value = "60")]
    disconnect_timeout: u64,

    /// Keep alive timeout in seconds
    #[arg(long, default_value = "120")]
    keep_alive: u64,

    /// Number of worker threads
    #[arg(long, default_value = "1")]
    workers: usize,

    /// Server hostname
    #[arg(long, default_value = "localhost")]
    hostname: String,

    /// Bind address
    #[arg(long, default_value = "0.0.0.0:5000")]
    bind: String,
}

#[derive(Clone, Copy, ValueEnum)]
enum StorageType {
    Mem,
    File,
}

impl Args {
    fn create_storage_service(&self) -> Result<StorageService, &'static str> {
        match self.get_storage_type() {
            StorageType::Mem => Ok(StorageService::new_memory()),
            StorageType::File => {
                if let Some(data_dir) = &self.data_dir {
                    Ok(StorageService::new_filesystem(data_dir))
                } else {
                    Err("--data-dir required when using file storage")
                }
            }
        }
    }

    fn get_storage_type(&self) -> StorageType {
        if self.data_dir.is_some() && matches!(self.storage, StorageType::Mem) {
            StorageType::File
        } else {
            self.storage
        }
    }

    fn get_upload_limits(&self) -> Result<UploadLimits, &'static str> {
        if self.max_blob_size == 0 {
            return Err("max-blob-size cannot be zero");
        }

        if self.max_manifest_size == 0 {
            return Err("max-manifest-size cannot be zero");
        }

        if self.max_manifest_size > self.max_blob_size {
            return Err("max-manifest-size cannot be larger than max-blob-size");
        }

        Ok(UploadLimits {
            max_blob_size: self.max_blob_size,
            max_manifest_size: self.max_manifest_size,
        })
    }
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let args: &Args = Box::leak(Box::new(Args::parse()));

    HttpServer::new(|| {
        let storage_service = args.create_storage_service().expect("failed create storage service");
        let upload_limits = args.get_upload_limits().expect("invalid upload limits");

        App::new()
            .wrap(Logger::new(r#"%a "%r" %s %b %T"#))
            .wrap(
                middleware::DefaultHeaders::new()
                    .add(("Docker-Distribution-API-Version", "registry/2.0"))
                    .add(("Cache-Control", "no-cache")),
            )
            .wrap(middleware::NormalizePath::trim())
            .app_data(web::PayloadConfig::new(upload_limits.max_blob_size))
            .app_data(
                web::JsonConfig::default()
                    .limit(upload_limits.max_manifest_size)
                    .error_handler(|err, _| {
                        log::warn!("JSON payload error: {err}");
                        actix_web::error::InternalError::from_response(
                            err,
                            actix_web::HttpResponse::from_error(DistributionError::ManifestTooLarge),
                        )
                        .into()
                    }),
            )
            .app_data(web::Data::new(storage_service))
            .app_data(web::Data::new(upload_limits))
            .configure(distribution::configure_routes)
    })
    .client_request_timeout(Duration::from_secs(args.request_timeout))
    .client_disconnect_timeout(Duration::from_secs(args.disconnect_timeout))
    .keep_alive(Duration::from_secs(args.keep_alive))
    .server_hostname(&args.hostname)
    .workers(args.workers)
    .bind(&args.bind)?
    .run()
    .await
}
