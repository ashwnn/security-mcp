use anyhow::{Result, bail};
use serde_json::Value;

use crate::types::PackageRef;

pub fn parse_dependency_file(file_type: &str, content: &str) -> Result<Vec<PackageRef>> {
    match file_type {
        "requirements.txt" => parse_requirements_txt(content),
        "package.json" => parse_package_json(content),
        "poetry.lock" => parse_poetry_lock(content),
        "go.mod" => parse_go_mod(content),
        "Cargo.toml" => parse_cargo_toml(content),
        other => bail!("unsupported file type: {other}"),
    }
}

pub fn parse_requirements_txt(content: &str) -> Result<Vec<PackageRef>> {
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split("==").collect();
        if parts.len() == 2 {
            out.push(PackageRef {
                name: parts[0].trim().to_string(),
                version: Some(parts[1].trim().to_string()),
            });
        }
    }
    Ok(out)
}

pub fn parse_package_json(content: &str) -> Result<Vec<PackageRef>> {
    let v: Value = serde_json::from_str(content)?;
    let mut out = Vec::new();
    for section in ["dependencies", "devDependencies"] {
        if let Some(obj) = v.get(section).and_then(Value::as_object) {
            for (name, version) in obj {
                out.push(PackageRef {
                    name: name.to_string(),
                    version: version.as_str().map(ToString::to_string),
                });
            }
        }
    }
    Ok(out)
}

pub fn parse_poetry_lock(content: &str) -> Result<Vec<PackageRef>> {
    let mut out = Vec::new();
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("name = ") {
            name = Some(
                line.trim_start_matches("name = ")
                    .trim_matches('"')
                    .to_string(),
            );
        } else if line.starts_with("version = ") {
            version = Some(
                line.trim_start_matches("version = ")
                    .trim_matches('"')
                    .to_string(),
            );
        } else if line == "[[package]]"
            && let (Some(n), Some(v)) = (name.take(), version.take())
        {
            out.push(PackageRef {
                name: n,
                version: Some(v),
            });
        }
    }
    if let (Some(n), Some(v)) = (name, version) {
        out.push(PackageRef {
            name: n,
            version: Some(v),
        });
    }
    Ok(out)
}

pub fn parse_go_mod(content: &str) -> Result<Vec<PackageRef>> {
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("require ") {
            let parts = line
                .trim_start_matches("require ")
                .split_whitespace()
                .collect::<Vec<_>>();
            if parts.len() >= 2 {
                out.push(PackageRef {
                    name: parts[0].to_string(),
                    version: Some(parts[1].to_string()),
                });
            }
        }
    }
    Ok(out)
}

pub fn parse_cargo_toml(content: &str) -> Result<Vec<PackageRef>> {
    let mut out = Vec::new();
    let mut in_deps = false;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_deps = line == "[dependencies]";
            continue;
        }
        if in_deps && line.contains('=') {
            let mut parts = line.splitn(2, '=');
            let name = parts.next().unwrap_or_default().trim();
            let value = parts.next().unwrap_or_default().trim().trim_matches('"');
            if !name.is_empty() {
                out.push(PackageRef {
                    name: name.to_string(),
                    version: if value.is_empty() {
                        None
                    } else {
                        Some(value.to_string())
                    },
                });
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_requirements() {
        let deps = parse_requirements_txt("requests==2.31.0\nflask==3.0.0\n").expect("deps");
        assert_eq!(deps.len(), 2);
    }

    #[test]
    fn parse_package_json_dependencies() {
        let deps = parse_package_json(r#"{"dependencies":{"react":"18.0.0"}}"#).expect("deps");
        assert_eq!(deps[0].name, "react");
    }
}
