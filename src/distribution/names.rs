use std::sync::LazyLock;

use regex_lite::Regex;
use thiserror::Error;

pub const NAME_COMPONENT_MIN_LENGTH: usize = 2;
pub const NAME_MIN_COMPONENTS: usize = 1;
pub const NAME_TOTAL_LENGTH_MAX: usize = 255;

#[derive(Error, Debug)]
pub enum NameError {
    #[error("repository name component must be {NAME_COMPONENT_MIN_LENGTH} or more characters")]
    NameComponentShort,
    #[error("repository name must have at least {NAME_MIN_COMPONENTS} components")]
    NameMissingComponents,
    #[error("repository name must not be more than {NAME_TOTAL_LENGTH_MAX} characters")]
    NameTooLong,
    #[error("repository name component must match \"[a-z0-9]+(?:[._-][a-z0-9]+)*\"")]
    NameComponentInvalid,
}

static NAME_COMPONENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)]
    Regex::new(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$").unwrap()
});

/// Ensures the repository name is valid for use in the registry. This function
/// accepts a superset of what might be accepted by Docker Hub. If the name
/// does not pass validation, an error, describing the conditions, is returned.
///
/// Effectively, the name should comply with the following grammar:
///
/// ```text
/// alpha-numeric := /[a-z0-9]+/
/// separator := /[._-]/
/// component := alpha-numeric [separator alpha-numeric]*
/// namespace := component ['/' component]*
/// ```
///
/// The result of the production, known as the "namespace", should be limited
/// to 255 characters.
pub fn validate_repository_name(name: &str) -> Result<(), NameError> {
    if name.len() > NAME_TOTAL_LENGTH_MAX {
        return Err(NameError::NameTooLong);
    }

    let components: Vec<&str> = name.split('/').collect();

    if components.len() < NAME_MIN_COMPONENTS {
        return Err(NameError::NameMissingComponents);
    }

    for component in components {
        if component.len() < NAME_COMPONENT_MIN_LENGTH {
            return Err(NameError::NameComponentShort);
        }

        if !NAME_COMPONENT_RE.is_match(component) {
            return Err(NameError::NameComponentInvalid);
        }
    }

    Ok(())
}

/// Validates a tag name according to Docker's tag naming rules
pub fn validate_tag_name(tag: &str) -> bool {
    let tag_regex = Regex::new(r"^[\w][\w.-]{0,127}$").unwrap();
    tag_regex.is_match(tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repository_name_validation_valid_names() {
        let long_name_255 = "a".repeat(255);
        let valid_names = vec![
            "short",
            "simple/name",
            "library/ubuntu",
            "docker/stevvooe/app",
            "aa/aa/aa/aa/aa/aa/aa/aa/aa/bb/bb/bb/bb/bb/bb",
            "aa/aa/bb/bb/bb",
            "foo.com/bar/baz",
            "blog.foo.com/bar/baz",
            "asdf",
            "aa-a/aa",
            "aa/aa",
            "a-a/a-a",
            long_name_255.as_str(), // 255 character name
        ];

        for name in valid_names {
            assert!(
                validate_repository_name(name).is_ok(),
                "Repository name '{name}' should be valid"
            );
        }
    }

    #[test]
    fn test_repository_name_validation_short_components() {
        let names_with_short_components = vec!["a/a/a/b/b", "a/a/a/a/", "a"];

        for name in names_with_short_components {
            let result = validate_repository_name(name);
            assert!(
                matches!(result, Err(NameError::NameComponentShort)),
                "Repository name '{name}' should fail with NameComponentShort, got {result:?}"
            );
        }
    }

    #[test]
    fn test_repository_name_validation_invalid_components() {
        let names_with_invalid_components = vec!["asdf$$^/aa", "a-/a/a/a"];

        for name in names_with_invalid_components {
            let result = validate_repository_name(name);
            assert!(
                matches!(result, Err(NameError::NameComponentInvalid)),
                "Repository name '{name}' should fail with NameComponentInvalid, got {result:?}"
            );
        }
    }

    #[test]
    fn test_repository_name_validation_too_long() {
        let long_name_256 = "a".repeat(256);
        let result = validate_repository_name(&long_name_256);
        assert!(
            matches!(result, Err(NameError::NameTooLong)),
            "256 character name should fail with NameTooLong, got {result:?}"
        );
    }

    #[test]
    fn test_tag_name_validation_valid_tags() {
        let long_tag_128 = "a".repeat(128);
        let valid_tags = vec![
            "latest",
            "v1.0.0",
            "main",
            "feature-branch",
            "test_tag",
            "tag.with.dots",
            "123",
            "a",
            "valid-tag",
            "valid.tag",
            "A", // uppercase is allowed in tags
            "Tag-With-CAPS",
            long_tag_128.as_str(), // exactly 128 chars (max allowed)
        ];

        for tag in valid_tags {
            assert!(validate_tag_name(tag), "Tag '{tag}' should be valid");
        }
    }

    #[test]
    fn test_tag_name_validation_invalid_tags() {
        let long_tag_129 = "a".repeat(129);
        let invalid_tags = vec![
            "",                    // empty string
            long_tag_129.as_str(), // too long (>128 chars)
            "-starts-with-dash",   // starts with dash
            ".starts-with-dot",    // starts with dot
            " starts-with-space",  // starts with space
            "has spaces",          // contains spaces
            "has@symbol",          // contains invalid symbol
            "has#hash",            // contains hash
            "has$dollar",          // contains dollar sign
        ];

        for tag in invalid_tags {
            assert!(!validate_tag_name(tag), "Tag '{tag}' should be invalid");
        }
    }

    #[test]
    fn test_repository_name_component_regexp_valid() {
        let valid_components = vec![
            "hello",
            "hello-world",
            "hello.world",
            "hello_world",
            "hello-world.test_case",
            "a1b2c3",
            "test123",
            "ab",             // minimum length
            "a0",             // alphanumeric mix
            "test.case_name", // mixed separators
        ];

        for component in valid_components {
            assert!(
                NAME_COMPONENT_RE.is_match(component),
                "Component '{component}' should be valid"
            );
        }
    }

    #[test]
    fn test_repository_name_component_regexp_invalid() {
        let invalid_components = vec![
            "Hello",       // uppercase
            "-hello",      // starts with separator
            "hello-",      // ends with separator
            ".hello",      // starts with separator
            "hello.",      // ends with separator
            "_hello",      // starts with separator
            "hello_",      // ends with separator
            "hel--lo",     // double separator
            "hel..lo",     // double separator
            "hel__lo",     // double separator
            "",            // empty
            "123-",        // ends with separator
            "hello world", // contains space
            "hello@world", // contains invalid character
        ];

        for component in invalid_components {
            assert!(
                !NAME_COMPONENT_RE.is_match(component),
                "Component '{component}' should be invalid"
            );
        }
    }

    #[test]
    fn test_real_examples() {
        let repository_names = vec![
            "alpine",
            "docker.io/nginx",
            "ghcr.io/devcontainers/features/docker-in-docker",
            "library/ubuntu",
        ];
        for name in repository_names {
            assert!(
                validate_repository_name(name).is_ok(),
                "Repository name '{name}' should be valid"
            );
        }

        let tag_names = vec!["latest", "v1.0.0", "main", "feature-branch"];
        for tag in tag_names {
            assert!(validate_tag_name(tag), "Tag '{tag}' should be valid");
        }
    }
}
