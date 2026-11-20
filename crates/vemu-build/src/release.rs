//! Which Alpine release to build from, and where its minirootfs is.
//!
//! - A branch (`latest-stable`, `v3.24`): `<mirror>/<branch>/releases/<arch>/latest-releases.yaml`
//!   lists the branch's current release; its `alpine-minirootfs` entry
//!   names the tarball and its SHA-256.
//! - An exact release (`3.24.4`): the tarball
//!   `<mirror>/v3.24/releases/<arch>/alpine-minirootfs-3.24.4-<arch>.tar.gz`
//!   and its `.sha256` file next to it.
//!
//! Everything read from the network is checked before use: names must be
//! exactly `alpine-minirootfs-<version>-<arch>.tar.gz`, branches `vN.M`,
//! versions dotted numbers, digests 64 hex digits.

use std::fmt;

use crate::sha256::is_hex_digest;

/// The `alpine =` setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Spec {
    /// `latest-stable` (the default).
    LatestStable,
    /// A stable branch, `v3.24`.
    Branch(String),
    /// An exact release, `3.24.4`.
    Exact(String),
}

impl fmt::Display for Spec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Spec::LatestStable => f.write_str("latest-stable"),
            Spec::Branch(b) => f.write_str(b),
            Spec::Exact(v) => f.write_str(v),
        }
    }
}

fn is_number(s: &str) -> bool {
    !s.is_empty() && s.len() <= 6 && s.bytes().all(|b| b.is_ascii_digit())
}

/// `vN.M`.
pub fn is_branch(s: &str) -> bool {
    s.strip_prefix('v')
        .and_then(|r| r.split_once('.'))
        .is_some_and(|(a, b)| is_number(a) && is_number(b))
}

/// `N.M.P`.
pub fn is_version(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| is_number(p))
}

impl Spec {
    pub fn parse(s: &str) -> Result<Spec, String> {
        if s == "latest-stable" {
            Ok(Spec::LatestStable)
        } else if is_branch(s) {
            Ok(Spec::Branch(s.to_string()))
        } else if is_version(s) {
            Ok(Spec::Exact(s.to_string()))
        } else if s == "edge" {
            Err("edge has no releases (no minirootfs); use latest-stable, a branch like v3.24 or a release like 3.24.4".into())
        } else {
            Err(format!(
                "expected latest-stable, a branch like v3.24 or a release like 3.24.4, got {s:?}"
            ))
        }
    }

    /// The branch directory of an exact release (`3.24.4` -> `v3.24`).
    pub fn exact_branch(version: &str) -> String {
        let mut it = version.split('.');
        let (a, b) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
        format!("v{a}.{b}")
    }
}

/// A resolved release: one minirootfs tarball.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// `3.24.4`.
    pub version: String,
    /// `v3.24`: the repositories the image uses.
    pub branch: String,
    /// `aarch64` or `x86_64`.
    pub arch: String,
    /// `alpine-minirootfs-3.24.4-aarch64.tar.gz`.
    pub file: String,
    /// Lower-case hex.
    pub sha256: String,
    /// Published size in bytes, when known.
    pub size: Option<u64>,
}

impl Release {
    /// The tarball's URL under `mirror` (no trailing slash).
    pub fn url(&self, mirror: &str) -> String {
        format!(
            "{mirror}/{}/releases/{}/{}",
            self.branch, self.arch, self.file
        )
    }
}

/// `alpine-minirootfs-<version>-<arch>.tar.gz`.
pub fn tarball_name(version: &str, arch: &str) -> String {
    format!("alpine-minirootfs-{version}-{arch}.tar.gz")
}

/// URL of `latest-releases.yaml` for a branch spec.
pub fn yaml_url(mirror: &str, branch: &str, arch: &str) -> String {
    format!("{mirror}/{branch}/releases/{arch}/latest-releases.yaml")
}

/// URL of the `.sha256` file of an exact release.
pub fn sha256_url(mirror: &str, version: &str, arch: &str) -> String {
    format!(
        "{mirror}/{}/releases/{arch}/{}.sha256",
        Spec::exact_branch(version),
        tarball_name(version, arch)
    )
}

/// The `alpine-minirootfs` entry of a `latest-releases.yaml` for `arch`.
///
/// The file is a YAML list of flat mappings (`-` items with `key: value`
/// lines, plus `desc: |` blocks); only that much YAML is understood.
pub fn parse_latest_releases(yaml: &str, arch: &str) -> Result<Release, String> {
    let mut items: Vec<Vec<(String, String)>> = Vec::new();
    for line in yaml.lines() {
        let trimmed = line.trim_end();
        if trimmed == "---" || trimmed.trim().is_empty() || trimmed.trim_start().starts_with('#') {
            continue;
        }
        if trimmed == "-" || trimmed.starts_with("- ") {
            items.push(Vec::new());
            let rest = trimmed[1..].trim();
            if let Some(kv) = (!rest.is_empty()).then_some(rest) {
                push_kv(items.last_mut().expect("just pushed"), kv);
            }
            continue;
        }
        // Keys of an item are indented by exactly two spaces; deeper lines
        // belong to block scalars (desc: |).
        let Some(rest) = trimmed.strip_prefix("  ") else {
            continue;
        };
        if rest.starts_with(' ') {
            continue;
        }
        if let Some(item) = items.last_mut() {
            push_kv(item, rest);
        }
    }
    let item = items
        .iter()
        .find(|i| get(i, "flavor") == Some("alpine-minirootfs") && get(i, "arch") == Some(arch))
        .ok_or_else(|| format!("no alpine-minirootfs entry for {arch} in latest-releases.yaml"))?;
    let field = |k: &str| {
        get(item, k).ok_or_else(|| format!("latest-releases.yaml: the minirootfs entry has no {k}"))
    };
    let version = field("version")?.to_string();
    let branch = field("branch")?.to_string();
    let file = field("file")?.to_string();
    let sha256 = field("sha256")?.to_ascii_lowercase();
    if !is_version(&version) {
        return Err(format!("latest-releases.yaml: bad version {version:?}"));
    }
    if !is_branch(&branch) || branch != Spec::exact_branch(&version) {
        return Err(format!(
            "latest-releases.yaml: branch {branch:?} does not match version {version}"
        ));
    }
    if file != tarball_name(&version, arch) {
        return Err(format!(
            "latest-releases.yaml: unexpected file name {file:?}"
        ));
    }
    if !is_hex_digest(&sha256) {
        return Err(format!("latest-releases.yaml: bad sha256 {sha256:?}"));
    }
    let size = get(item, "size")
        .map(|s| {
            s.parse::<u64>()
                .map_err(|_| format!("latest-releases.yaml: bad size {s:?}"))
        })
        .transpose()?;
    Ok(Release {
        version,
        branch,
        arch: arch.to_string(),
        file,
        sha256,
        size,
    })
}

fn push_kv(item: &mut Vec<(String, String)>, kv: &str) {
    if let Some((k, v)) = kv.split_once(':') {
        let v = v.trim();
        let v = v
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(v);
        item.push((k.trim().to_string(), v.to_string()));
    }
}

fn get<'a>(item: &'a [(String, String)], key: &str) -> Option<&'a str> {
    item.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

/// The digest in a `.sha256` file (`<hex>  <name>`), which must name
/// `file`.
pub fn parse_sha256_file(text: &str, file: &str) -> Result<String, String> {
    let line = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .ok_or("empty .sha256 file")?;
    let mut words = line.split_whitespace();
    let digest = words.next().unwrap_or("").to_ascii_lowercase();
    let name = words.next().map(|n| n.trim_start_matches('*'));
    if !is_hex_digest(&digest) {
        return Err(format!("bad digest in the .sha256 file: {line:?}"));
    }
    if name.is_some_and(|n| n != file) {
        return Err(format!(
            "the .sha256 file is for {:?}, not {file}",
            name.unwrap_or("")
        ));
    }
    Ok(digest)
}

/// The release of an exact version, given its `.sha256` file.
pub fn exact_release(version: &str, arch: &str, sha_file: &str) -> Result<Release, String> {
    let file = tarball_name(version, arch);
    let sha256 = parse_sha256_file(sha_file, &file)?;
    Ok(Release {
        version: version.to_string(),
        branch: Spec::exact_branch(version),
        arch: arch.to_string(),
        file,
        sha256,
        size: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: &str = "---
-
  title: \"Raspberry Pi\"
  desc: |
    First generation Pis including Zero/W (armhf).
    flavor: not-this-one
  branch: v3.24
  arch: aarch64
  version: 3.24.4
  flavor: alpine-rpi
  file: alpine-rpi-3.24.4-aarch64.tar.gz
  sha256: 47524dfd4dc91f7039e1fea3cd70dff2d4c7d355f8bc57033b6d495d30d5a214
-
  title: \"Mini root filesystem\"
  desc: |
    Minimal root filesystem.
    For use in containers
  branch: v3.24
  arch: aarch64
  version: 3.24.4
  flavor: alpine-minirootfs
  file: alpine-minirootfs-3.24.4-aarch64.tar.gz
  iso: alpine-minirootfs-3.24.4-aarch64.tar.gz
  date: 2026-11-05
  time: 09:19:25
  size: 4029843
  sha256: 4B14C18F7E90A063B61462EA1462A5732C154BF6ADAD594974FE6487CD98A8DE
";

    #[test]
    fn specs() {
        assert_eq!(Spec::parse("latest-stable"), Ok(Spec::LatestStable));
        assert_eq!(Spec::parse("v3.24"), Ok(Spec::Branch("v3.24".into())));
        assert_eq!(Spec::parse("3.24.4"), Ok(Spec::Exact("3.24.4".into())));
        assert!(Spec::parse("edge").unwrap_err().contains("no releases"));
        for bad in ["", "v3", "3.24", "v3.x", "3.24.4.1", "../x", "latest"] {
            assert!(Spec::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(Spec::exact_branch("3.24.4"), "v3.24");
        assert_eq!(
            sha256_url("https://m/alpine", "3.24.4", "x86_64"),
            "https://m/alpine/v3.24/releases/x86_64/alpine-minirootfs-3.24.4-x86_64.tar.gz.sha256"
        );
        assert_eq!(
            yaml_url("https://m/alpine", "latest-stable", "aarch64"),
            "https://m/alpine/latest-stable/releases/aarch64/latest-releases.yaml"
        );
    }

    #[test]
    fn latest_releases() {
        let r = parse_latest_releases(YAML, "aarch64").unwrap();
        assert_eq!(
            r,
            Release {
                version: "3.24.4".into(),
                branch: "v3.24".into(),
                arch: "aarch64".into(),
                file: "alpine-minirootfs-3.24.4-aarch64.tar.gz".into(),
                sha256: "4b14c18f7e90a063b61462ea1462a5732c154bf6adad594974fe6487cd98a8de".into(),
                size: Some(4029843),
            }
        );
        assert_eq!(
            r.url("https://dl-cdn.alpinelinux.org/alpine"),
            "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/aarch64/alpine-minirootfs-3.24.4-aarch64.tar.gz"
        );
        assert!(
            parse_latest_releases(YAML, "x86_64")
                .unwrap_err()
                .contains("no alpine-minirootfs")
        );
        // Hostile or broken entries are refused.
        for (from, to) in [
            (
                "file: alpine-minirootfs-3.24.4-aarch64.tar.gz",
                "file: ../../etc/passwd",
            ),
            ("sha256: 4B14", "sha256: ZZ14"),
            (
                "  branch: v3.24\n  arch: aarch64\n  version: 3.24.4\n  flavor: alpine-minirootfs",
                "  branch: v3.23\n  arch: aarch64\n  version: 3.24.4\n  flavor: alpine-minirootfs",
            ),
            (
                "version: 3.24.4\n  flavor: alpine-minirootfs",
                "version: 3.24.4;rm\n  flavor: alpine-minirootfs",
            ),
        ] {
            let y = YAML.replace(from, to);
            assert_ne!(y, YAML, "{from}");
            assert!(parse_latest_releases(&y, "aarch64").is_err(), "{to}");
        }
    }

    #[test]
    fn sha256_files() {
        let d = "4b14c18f7e90a063b61462ea1462a5732c154bf6adad594974fe6487cd98a8de";
        let r = exact_release(
            "3.24.4",
            "aarch64",
            &format!("{d}  alpine-minirootfs-3.24.4-aarch64.tar.gz\n"),
        )
        .unwrap();
        assert_eq!((r.branch.as_str(), r.sha256.as_str()), ("v3.24", d));
        assert!(parse_sha256_file(&format!("{d}  other.tar.gz"), "x.tar.gz").is_err());
        assert!(parse_sha256_file("nothex  x", "x").is_err());
        assert!(parse_sha256_file("", "x").is_err());
        assert_eq!(parse_sha256_file(&format!("{d}\n"), "x").unwrap(), d);
    }
}
