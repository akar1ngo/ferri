//! Implements the `application/vnd.oci.image.config.v1+json` media type as
//! defined in OCI Image Configuration v1.0.1.

use std::collections::BTreeMap;

use chrono::DateTime;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::digest::parse_digest;

/// The execution parameters which SHOULD be used as a base when running a container using the image.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Config {
    /// The username or UID which is a platform-specific structure that allows specific control
    /// over which user the process run as.
    #[serde(rename = "User", skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,

    /// A set of ports to expose from a container running this image.
    /// Keys can be in the format of: port/tcp, port/udp, port with the default protocol being tcp.
    #[serde(rename = "ExposedPorts", skip_serializing_if = "Option::is_none")]
    pub exposed_ports: Option<BTreeMap<String, EmptyObject>>,

    /// Entries are in the format of VARNAME=VARVALUE.
    /// These values act as defaults and are merged with any specified when creating a container.
    #[serde(rename = "Env", skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,

    /// A list of arguments to use as the command to execute when the container starts.
    #[serde(rename = "Entrypoint", skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Vec<String>>,

    /// Default arguments to the entrypoint of the container.
    #[serde(rename = "Cmd", skip_serializing_if = "Option::is_none")]
    pub cmd: Option<Vec<String>>,

    /// A set of directories describing where the process is likely write data specific to a container instance.
    #[serde(rename = "Volumes", skip_serializing_if = "Option::is_none")]
    pub volumes: Option<BTreeMap<String, EmptyObject>>,

    /// Sets the current working directory of the entrypoint process in the container.
    #[serde(rename = "WorkingDir", skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,

    /// The field contains arbitrary metadata for the container.
    #[serde(rename = "Labels", skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,

    /// The field contains the system call signal that will be sent to the container to exit.
    #[serde(rename = "StopSignal", skip_serializing_if = "Option::is_none")]
    pub stop_signal: Option<String>,
}

/// Represents an empty JSON object `{}` used for ExposedPorts and Volumes.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct EmptyObject {}

/// The rootfs key references the layer content addresses used by the image.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Rootfs {
    /// MUST be set to "layers".
    #[serde(rename = "type")]
    pub fs_type: String,

    /// An array of layer content hashes (DiffIDs), in order from first to last.
    pub diff_ids: Vec<String>,
}

/// Describes the history of each layer.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct History {
    /// A combined date and time at which the layer was created, formatted as defined by RFC 3339.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    /// The author of the build point.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,

    /// The command which created the layer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,

    /// A custom message set when creating the layer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// This field is used to mark if the history item created a filesystem diff.
    /// It is set to true if this history item doesn't correspond to an actual layer in the rootfs section.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub empty_layer: Option<bool>,
}

/// OCI Image Configuration
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct ImageConfig {
    /// An combined date and time at which the image was created, formatted as defined by RFC 3339.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    /// Gives the name and/or email address of the person or entity which created and is responsible for maintaining the image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,

    /// The CPU architecture which the binaries in this image are built to run on.
    pub architecture: String,

    /// The name of the operating system which the image is built to run on.
    pub os: String,

    /// The execution parameters which SHOULD be used as a base when running a container using the image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<Config>,

    /// The rootfs key references the layer content addresses used by the image.
    pub rootfs: Rootfs,

    /// Describes the history of each layer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<Vec<History>>,
}

impl ImageConfig {
    /// Creates a new ImageConfig with the required fields.
    pub fn new(architecture: String, os: String, rootfs: Rootfs) -> Self {
        Self {
            created: None,
            author: None,
            architecture,
            os,
            config: None,
            rootfs,
            history: None,
        }
    }

    /// Validates the image configuration according to the specification.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate architecture is not empty
        if self.architecture.is_empty() {
            return Err(ConfigError::EmptyArchitecture);
        }

        // Validate OS is not empty
        if self.os.is_empty() {
            return Err(ConfigError::EmptyOs);
        }

        // Validate rootfs
        self.rootfs.validate()?;

        // Validate config if present
        if let Some(ref config) = self.config {
            config.validate()?;
        }

        // Validate history if present
        if let Some(ref history) = self.history {
            for (idx, entry) in history.iter().enumerate() {
                entry
                    .validate()
                    .map_err(|e| ConfigError::InvalidHistory(idx, Box::new(e)))?;
            }
        }

        // Validate created timestamp if present
        if let Some(ref created) = self.created {
            validate_rfc3339_timestamp(created).map_err(|_| ConfigError::InvalidCreatedTimestamp(created.clone()))?;
        }

        Ok(())
    }

    /// Sets the creation timestamp.
    pub fn set_created(&mut self, created: String) {
        self.created = Some(created);
    }

    /// Sets the author.
    pub fn set_author(&mut self, author: String) {
        self.author = Some(author);
    }

    /// Sets the config.
    pub fn set_config(&mut self, config: Config) {
        self.config = Some(config);
    }

    /// Sets the history.
    pub fn set_history(&mut self, history: Vec<History>) {
        self.history = Some(history);
    }
}

impl Rootfs {
    /// Creates a new Rootfs with the required fields.
    pub fn new(diff_ids: Vec<String>) -> Self {
        Self {
            fs_type: "layers".to_string(),
            diff_ids,
        }
    }

    /// Validates the rootfs according to the specification.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate type is "layers"
        if self.fs_type != "layers" {
            return Err(ConfigError::InvalidRootfsType(self.fs_type.clone()));
        }

        // Validate all diff_ids are valid digests
        for (idx, diff_id) in self.diff_ids.iter().enumerate() {
            parse_digest(diff_id).map_err(|_| ConfigError::InvalidDiffId(idx, diff_id.clone()))?;
        }

        Ok(())
    }
}

impl Config {
    /// Creates a new empty Config.
    pub fn new() -> Self {
        Self {
            user: None,
            exposed_ports: None,
            env: None,
            entrypoint: None,
            cmd: None,
            volumes: None,
            working_dir: None,
            labels: None,
            stop_signal: None,
        }
    }

    /// Validates the config according to the specification.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate environment variables format if present
        if let Some(ref env) = self.env {
            for (idx, env_var) in env.iter().enumerate() {
                if !env_var.contains('=') {
                    return Err(ConfigError::InvalidEnvFormat(idx, env_var.clone()));
                }
            }
        }

        // Validate exposed ports format if present
        if let Some(ref ports) = self.exposed_ports {
            for port in ports.keys() {
                validate_port_format(port)?;
            }
        }

        // Validate stop signal format if present
        if let Some(ref signal) = self.stop_signal {
            validate_stop_signal(signal)?;
        }

        Ok(())
    }

    /// Adds an environment variable.
    pub fn add_env(&mut self, name: &str, value: &str) {
        let env_var = format!("{name}={value}");
        self.env.get_or_insert_with(Vec::new).push(env_var);
    }

    /// Adds an exposed port.
    pub fn add_exposed_port(&mut self, port: &str) {
        self.exposed_ports
            .get_or_insert_with(BTreeMap::new)
            .insert(port.to_string(), EmptyObject {});
    }

    /// Adds a volume.
    pub fn add_volume(&mut self, path: &str) {
        self.volumes
            .get_or_insert_with(BTreeMap::new)
            .insert(path.to_string(), EmptyObject {});
    }

    /// Adds a label.
    pub fn add_label(&mut self, key: &str, value: &str) {
        self.labels
            .get_or_insert_with(BTreeMap::new)
            .insert(key.to_string(), value.to_string());
    }
}

impl History {
    /// Creates a new History entry.
    pub fn new() -> Self {
        Self {
            created: None,
            author: None,
            created_by: None,
            comment: None,
            empty_layer: None,
        }
    }

    /// Validates the history entry according to the specification.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate created timestamp if present
        if let Some(ref created) = self.created {
            validate_rfc3339_timestamp(created).map_err(|_| ConfigError::InvalidCreatedTimestamp(created.clone()))?;
        }

        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for History {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur when working with Image Configurations.
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Architecture cannot be empty")]
    EmptyArchitecture,

    #[error("OS cannot be empty")]
    EmptyOs,

    #[error("Invalid rootfs type: {0}, expected 'layers'")]
    InvalidRootfsType(String),

    #[error("Invalid diff_id at index {0}: {1}")]
    InvalidDiffId(usize, String),

    #[error("Invalid environment variable format at index {0}: {1} (expected VARNAME=VARVALUE)")]
    InvalidEnvFormat(usize, String),

    #[error("Invalid port format: {0}")]
    InvalidPortFormat(String),

    #[error("Invalid stop signal: {0}")]
    InvalidStopSignal(String),

    #[error("Invalid created timestamp: {0}")]
    InvalidCreatedTimestamp(String),

    #[error("Invalid history entry at index {0}")]
    InvalidHistory(usize, Box<ConfigError>),
}

/// Validates a port format (port/tcp, port/udp, or just port).
fn validate_port_format(port: &str) -> Result<(), ConfigError> {
    if port.is_empty() {
        return Err(ConfigError::InvalidPortFormat(port.to_string()));
    }

    // Check if it has a protocol suffix
    if let Some((port_num, protocol)) = port.rsplit_once('/') {
        // Validate protocol
        if !matches!(protocol, "tcp" | "udp") {
            return Err(ConfigError::InvalidPortFormat(port.to_string()));
        }
        // Validate port number
        validate_port_number(port_num)?;
    } else {
        // Just a port number
        validate_port_number(port)?;
    }

    Ok(())
}

/// Validates that a string is a valid port number.
fn validate_port_number(port: &str) -> Result<(), ConfigError> {
    if port.is_empty() {
        return Err(ConfigError::InvalidPortFormat(port.to_string()));
    }

    match port.parse::<u16>() {
        Ok(num) if num > 0 => Ok(()),
        _ => Err(ConfigError::InvalidPortFormat(port.to_string())),
    }
}

/// Validates a stop signal format.
fn validate_stop_signal(signal: &str) -> Result<(), ConfigError> {
    if signal.is_empty() {
        return Err(ConfigError::InvalidStopSignal(signal.to_string()));
    }

    // Signal can be a signal name (SIGNAME format) or SIGRTMIN+number
    if signal.starts_with("SIG") || signal.starts_with("SIGRTMIN+") {
        Ok(())
    } else {
        Err(ConfigError::InvalidStopSignal(signal.to_string()))
    }
}

/// Validates RFC3339 timestamp format.
fn validate_rfc3339_timestamp(timestamp: &str) -> Result<(), ConfigError> {
    match DateTime::parse_from_rfc3339(timestamp) {
        Ok(_) => Ok(()),
        Err(_) => Err(ConfigError::InvalidCreatedTimestamp(timestamp.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn test_rootfs_creation() -> Result<(), Box<dyn Error>> {
        let diff_ids = vec![
            "sha256:c6f988f4874bb0add23a778f753c65efe992244e148a1d2ec2a8b664fb66bbd1".to_string(),
            "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef".to_string(),
        ];

        let rootfs = Rootfs::new(diff_ids.clone());
        assert_eq!(rootfs.fs_type, "layers");
        assert_eq!(rootfs.diff_ids, diff_ids);

        rootfs.validate()?;
        Ok(())
    }

    #[test]
    fn test_config_creation() -> Result<(), Box<dyn Error>> {
        let mut config = Config::new();
        config.add_env("PATH", "/usr/bin");
        config.add_env("FOO", "bar");
        config.add_exposed_port("8080/tcp");
        config.add_volume("/data");
        config.add_label("version", "1.0");

        config.validate()?;

        assert!(config.env.is_some());
        assert_eq!(config.env.as_ref().unwrap().len(), 2);
        assert!(config.exposed_ports.is_some());
        assert!(config.volumes.is_some());
        assert!(config.labels.is_some());

        Ok(())
    }

    #[test]
    fn test_image_config_creation() -> Result<(), Box<dyn Error>> {
        let diff_ids = vec!["sha256:c6f988f4874bb0add23a778f753c65efe992244e148a1d2ec2a8b664fb66bbd1".to_string()];
        let rootfs = Rootfs::new(diff_ids);

        let mut image_config = ImageConfig::new("amd64".to_string(), "linux".to_string(), rootfs);

        image_config.set_created("2015-10-31T22:22:56.015925234Z".to_string());
        image_config.set_author("Alyssa P. Hacker <alyspdev@example.com>".to_string());

        let mut config = Config::new();
        config.add_env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
        config.add_exposed_port("8080/tcp");
        image_config.set_config(config);

        image_config.validate()?;
        Ok(())
    }

    #[test]
    fn test_validation_errors() {
        // Test empty architecture
        let rootfs = Rootfs::new(vec![]);
        let mut config = ImageConfig::new("".to_string(), "linux".to_string(), rootfs);
        assert!(matches!(config.validate(), Err(ConfigError::EmptyArchitecture)));

        // Test empty OS
        let rootfs = Rootfs::new(vec![]);
        config = ImageConfig::new("amd64".to_string(), "".to_string(), rootfs);
        assert!(matches!(config.validate(), Err(ConfigError::EmptyOs)));

        // Test invalid rootfs type
        let mut rootfs = Rootfs::new(vec![]);
        rootfs.fs_type = "invalid".to_string();
        config = ImageConfig::new("amd64".to_string(), "linux".to_string(), rootfs);
        assert!(matches!(config.validate(), Err(ConfigError::InvalidRootfsType(_))));
    }

    #[test]
    fn test_example_from_spec() -> Result<(), Box<dyn Error>> {
        let json = r#"{
            "created": "2015-10-31T22:22:56.015925234Z",
            "author": "Alyssa P. Hacker <alyspdev@example.com>",
            "architecture": "amd64",
            "os": "linux",
            "config": {
                "User": "alice",
                "ExposedPorts": {
                    "8080/tcp": {}
                },
                "Env": [
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "FOO=oci_is_a",
                    "BAR=well_written_spec"
                ],
                "Entrypoint": [
                    "/bin/my-app-binary"
                ],
                "Cmd": [
                    "--foreground",
                    "--config",
                    "/etc/my-app.d/default.cfg"
                ],
                "Volumes": {
                    "/var/job-result-data": {},
                    "/var/log/my-app-logs": {}
                },
                "WorkingDir": "/home/alice",
                "Labels": {
                    "com.example.project.git.url": "https://example.com/project.git",
                    "com.example.project.git.commit": "45a939b2999782a3f005621a8d0f29aa387e1d6b"
                }
            },
            "rootfs": {
              "diff_ids": [
                "sha256:c6f988f4874bb0add23a778f753c65efe992244e148a1d2ec2a8b664fb66bbd1",
                "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"
              ],
              "type": "layers"
            },
            "history": [
              {
                "created": "2015-10-31T22:22:54.690851953Z",
                "created_by": "/bin/sh -c #(nop) ADD file:a3bc1e842b69636f9df5256c49c5374fb4eef1e281fe3f282c65fb853ee171c5 in /"
              },
              {
                "created": "2015-10-31T22:22:55.613815829Z",
                "created_by": "/bin/sh -c #(nop) CMD [\"sh\"]",
                "empty_layer": true
              }
            ]
        }"#;

        let config: ImageConfig = serde_json::from_str(json)?;
        config.validate()?;

        assert_eq!(config.architecture, "amd64");
        assert_eq!(config.os, "linux");
        assert!(config.config.is_some());
        assert!(config.history.is_some());

        let serialized = serde_json::to_string_pretty(&config)?;
        let roundtrip: ImageConfig = serde_json::from_str(&serialized)?;
        assert_eq!(config, roundtrip);

        Ok(())
    }

    #[test]
    fn test_port_validation() {
        assert!(validate_port_format("8080").is_ok());
        assert!(validate_port_format("8080/tcp").is_ok());
        assert!(validate_port_format("8080/udp").is_ok());

        assert!(validate_port_format("").is_err());
        assert!(validate_port_format("8080/http").is_err());
        assert!(validate_port_format("0").is_err());
        assert!(validate_port_format("abc").is_err());
    }

    #[test]
    fn test_stop_signal_validation() {
        assert!(validate_stop_signal("SIGTERM").is_ok());
        assert!(validate_stop_signal("SIGKILL").is_ok());
        assert!(validate_stop_signal("SIGRTMIN+3").is_ok());

        assert!(validate_stop_signal("").is_err());
        assert!(validate_stop_signal("TERM").is_err());
        assert!(validate_stop_signal("15").is_err());
    }

    #[test]
    fn test_rfc3339_validation() {
        assert!(validate_rfc3339_timestamp("2015-10-31T22:22:56.015925234Z").is_ok());
        assert!(validate_rfc3339_timestamp("2015-10-31T22:22:56+00:00").is_ok());
        assert!(validate_rfc3339_timestamp("2015-10-31T22:22:56-05:00").is_ok());

        assert!(validate_rfc3339_timestamp("").is_err());
        assert!(validate_rfc3339_timestamp("2015-10-31").is_err());
        assert!(validate_rfc3339_timestamp("22:22:56").is_err());
    }
}
