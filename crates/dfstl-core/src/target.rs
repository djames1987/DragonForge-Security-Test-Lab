use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::hash::{Sha256, hex_digest, sha256_file};

pub const EXPECTED_EXECUTABLES: [&str; 11] = [
    "dragonforge-desktop.exe",
    "dragonforge-security-center.exe",
    "dragonforge-file-vault.exe",
    "dragonforge-authenticator.exe",
    "dragonforge-security-scanner.exe",
    "dragonforge-integrity-monitor.exe",
    "dragonforge-network-guard.exe",
    "dragonforge-backup-recovery.exe",
    "dragonforge-secure-share.exe",
    "dragonforge-agent.exe",
    "dragonforge-privileged-service.exe",
];

#[derive(Debug)]
pub enum TargetError {
    Io(io::Error),
    RootNotFound(PathBuf),
    RootNotDirectory(PathBuf),
    NoCandidate(PathBuf),
    AmbiguousCandidates(Vec<PathBuf>),
    ExpectedFileIsSymlink(PathBuf),
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => f.write_str("target discovery I/O failure"),
            Self::RootNotFound(path) => {
                write!(f, "target root does not exist: {}", path.display())
            }
            Self::RootNotDirectory(path) => {
                write!(f, "target root is not a directory: {}", path.display())
            }
            Self::NoCandidate(path) => {
                write!(f, "no DragonForge target candidate found under {}", path.display())
            }
            Self::AmbiguousCandidates(paths) => {
                write!(f, "multiple DragonForge target candidates found ({})", paths.len())
            }
            Self::ExpectedFileIsSymlink(path) => {
                write!(f, "expected target file is a symlink: {}", path.display())
            }
        }
    }
}

impl std::error::Error for TargetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for TargetError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BuildInfo {
    pub version: Option<String>,
    pub release_channel: Option<String>,
    pub git_commit: Option<String>,
    pub git_tag: Option<String>,
    pub built_utc: Option<String>,
    pub platform: Option<String>,
    pub code_signing: Option<String>,
}

impl BuildInfo {
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut values = BTreeMap::new();
        for line in text.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            values.insert(key.trim().to_ascii_lowercase(), value.trim().to_owned());
        }

        Self {
            version: values.remove("version"),
            release_channel: values.remove("release channel"),
            git_commit: values.remove("git commit"),
            git_tag: values.remove("git tag"),
            built_utc: values.remove("built (utc)"),
            platform: values.remove("platform"),
            code_signing: values.remove("code signing"),
        }
    }

    #[must_use]
    pub fn has_identity_metadata(&self) -> bool {
        self.version.is_some() || self.git_commit.is_some() || self.git_tag.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetExecutable {
    pub name: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageManifestStatus {
    Absent,
    Valid,
    Invalid(String),
}

impl PackageManifestStatus {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Valid => "valid",
            Self::Invalid(_) => "invalid",
        }
    }

    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Invalid(detail) => Some(detail),
            Self::Absent | Self::Valid => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetInspection {
    pub root: PathBuf,
    pub complete: bool,
    pub build_fingerprint: String,
    pub build_info: Option<BuildInfo>,
    pub manifest_status: PackageManifestStatus,
    pub executables: Vec<TargetExecutable>,
    pub missing_executables: Vec<String>,
    pub unexpected_dragonforge_executables: Vec<String>,
}

impl TargetInspection {
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(output, "DragonForge target inspection");
        let _ = writeln!(output, "Root: {}", self.root.display());
        let _ = writeln!(output, "Complete: {}", self.complete);
        let _ = writeln!(output, "Build fingerprint: {}", self.build_fingerprint);
        let _ = writeln!(
            output,
            "Package manifest: {}",
            self.manifest_status.as_str()
        );

        if let Some(detail) = self.manifest_status.detail() {
            let _ = writeln!(output, "Manifest detail: {detail}");
        }

        if let Some(info) = &self.build_info {
            let _ = writeln!(
                output,
                "Version: {}",
                info.version.as_deref().unwrap_or("unknown")
            );
            let _ = writeln!(
                output,
                "Git commit: {}",
                info.git_commit.as_deref().unwrap_or("unknown")
            );
            let _ = writeln!(
                output,
                "Git tag: {}",
                info.git_tag.as_deref().unwrap_or("unknown")
            );
            let _ = writeln!(
                output,
                "Platform: {}",
                info.platform.as_deref().unwrap_or("unknown")
            );
        } else {
            let _ = writeln!(output, "BUILD-INFO.txt: absent");
        }

        let _ = writeln!(output);
        let _ = writeln!(
            output,
            "Executables: {}/{}",
            self.executables.len(),
            EXPECTED_EXECUTABLES.len()
        );
        for executable in &self.executables {
            let _ = writeln!(
                output,
                "  {}  {} bytes  {}",
                executable.name, executable.size_bytes, executable.sha256
            );
        }

        if !self.missing_executables.is_empty() {
            let _ = writeln!(output, "Missing executables:");
            for name in &self.missing_executables {
                let _ = writeln!(output, "  {name}");
            }
        }

        if !self.unexpected_dragonforge_executables.is_empty() {
            let _ = writeln!(output, "Unexpected DragonForge executables:");
            for name in &self.unexpected_dragonforge_executables {
                let _ = writeln!(output, "  {name}");
            }
        }

        output
    }

    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(output, "{{");
        let _ = writeln!(output, "  \"schema_version\": 1,");
        let _ = writeln!(
            output,
            "  \"root\": \"{}\",",
            json_escape(&self.root.to_string_lossy())
        );
        let _ = writeln!(output, "  \"complete\": {},", self.complete);
        let _ = writeln!(
            output,
            "  \"build_fingerprint\": \"{}\",",
            self.build_fingerprint
        );
        let _ = writeln!(
            output,
            "  \"manifest_status\": \"{}\",",
            self.manifest_status.as_str()
        );
        match self.manifest_status.detail() {
            Some(detail) => {
                let _ = writeln!(
                    output,
                    "  \"manifest_detail\": \"{}\",",
                    json_escape(detail)
                );
            }
            None => {
                let _ = writeln!(output, "  \"manifest_detail\": null,");
            }
        }

        match &self.build_info {
            Some(info) => {
                let _ = writeln!(output, "  \"build_info\": {{");
                write_optional_json(&mut output, "version", info.version.as_deref(), true);
                write_optional_json(
                    &mut output,
                    "release_channel",
                    info.release_channel.as_deref(),
                    true,
                );
                write_optional_json(
                    &mut output,
                    "git_commit",
                    info.git_commit.as_deref(),
                    true,
                );
                write_optional_json(&mut output, "git_tag", info.git_tag.as_deref(), true);
                write_optional_json(&mut output, "built_utc", info.built_utc.as_deref(), true);
                write_optional_json(&mut output, "platform", info.platform.as_deref(), true);
                write_optional_json(
                    &mut output,
                    "code_signing",
                    info.code_signing.as_deref(),
                    false,
                );
                let _ = writeln!(output, "  }},");
            }
            None => {
                let _ = writeln!(output, "  \"build_info\": null,");
            }
        }

        let _ = writeln!(output, "  \"executables\": [");
        for (index, executable) in self.executables.iter().enumerate() {
            let comma = if index + 1 == self.executables.len() {
                ""
            } else {
                ","
            };
            let _ = writeln!(
                output,
                "    {{\"name\": \"{}\", \"size_bytes\": {}, \"sha256\": \"{}\"}}{comma}",
                json_escape(&executable.name),
                executable.size_bytes,
                executable.sha256
            );
        }
        let _ = writeln!(output, "  ],");

        write_string_array(
            &mut output,
            "missing_executables",
            &self.missing_executables,
            true,
        );
        write_string_array(
            &mut output,
            "unexpected_dragonforge_executables",
            &self.unexpected_dragonforge_executables,
            false,
        );
        let _ = writeln!(output, "}}");
        output
    }
}

/// Returns immediate child directories that look like `DragonForge` build roots.
///
/// # Errors
///
/// Returns an error if the supplied root is missing, is not a directory, or
/// cannot be enumerated.
pub fn discover_candidates(root: &Path) -> Result<Vec<PathBuf>, TargetError> {
    validate_directory(root)?;

    let mut candidates = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            continue;
        }
        if looks_like_target(&entry.path())? {
            candidates.push(entry.path());
        }
    }
    candidates.sort();
    Ok(candidates)
}

/// Resolves an exact `DragonForge` target or exactly one immediate child target.
///
/// # Errors
///
/// Fails closed if no candidate exists or more than one candidate exists.
pub fn resolve_target(root: &Path) -> Result<PathBuf, TargetError> {
    validate_directory(root)?;

    if looks_like_target(root)? {
        return Ok(root.to_path_buf());
    }

    let candidates = discover_candidates(root)?;
    match candidates.as_slice() {
        [] => Err(TargetError::NoCandidate(root.to_path_buf())),
        [candidate] => Ok(candidate.clone()),
        _ => Err(TargetError::AmbiguousCandidates(candidates)),
    }
}

/// Inspects a resolved `DragonForge` target without executing target binaries.
///
/// # Errors
///
/// Returns an error if files cannot be safely read or if an expected
/// executable is represented by a symlink.
pub fn inspect_target(root: &Path) -> Result<TargetInspection, TargetError> {
    validate_directory(root)?;

    let mut executables = Vec::new();
    let mut missing_executables = Vec::new();

    for name in EXPECTED_EXECUTABLES {
        let path = root.join(name);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing_executables.push(name.to_owned());
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() {
            return Err(TargetError::ExpectedFileIsSymlink(path));
        }
        if !metadata.is_file() {
            missing_executables.push(name.to_owned());
            continue;
        }

        executables.push(TargetExecutable {
            name: name.to_owned(),
            size_bytes: metadata.len(),
            sha256: hex_digest(&sha256_file(&path)?),
        });
    }

    executables.sort_by(|left, right| left.name.cmp(&right.name));
    missing_executables.sort();

    let unexpected_dragonforge_executables = unexpected_executables(root)?;
    let build_info = read_build_info(root)?;
    let manifest_status = validate_package_manifest(root, &executables)?;
    let build_fingerprint = build_fingerprint(&executables);

    Ok(TargetInspection {
        root: root.to_path_buf(),
        complete: missing_executables.is_empty(),
        build_fingerprint,
        build_info,
        manifest_status,
        executables,
        missing_executables,
        unexpected_dragonforge_executables,
    })
}

fn validate_directory(path: &Path) -> Result<(), TargetError> {
    if !path.exists() {
        return Err(TargetError::RootNotFound(path.to_path_buf()));
    }
    if !path.is_dir() {
        return Err(TargetError::RootNotDirectory(path.to_path_buf()));
    }
    Ok(())
}

fn looks_like_target(path: &Path) -> Result<bool, TargetError> {
    if path.join("BUILD-INFO.txt").is_file() {
        return Ok(true);
    }

    for name in EXPECTED_EXECUTABLES {
        let candidate = path.join(name);
        if candidate.exists() {
            let metadata = fs::symlink_metadata(candidate)?;
            if metadata.is_file() && !metadata.file_type().is_symlink() {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn unexpected_executables(root: &Path) -> Result<Vec<String>, TargetError> {
    let expected: BTreeSet<&str> = EXPECTED_EXECUTABLES.into_iter().collect();
    let mut unexpected = Vec::new();

    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            continue;
        }

        let name = entry.file_name().to_string_lossy().into_owned();
        let lower = name.to_ascii_lowercase();
        if lower.starts_with("dragonforge-")
            && lower.ends_with(".exe")
            && !expected.contains(lower.as_str())
        {
            unexpected.push(name);
        }
    }

    unexpected.sort();
    Ok(unexpected)
}

fn read_build_info(root: &Path) -> Result<Option<BuildInfo>, TargetError> {
    let path = root.join("BUILD-INFO.txt");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() {
        return Err(TargetError::ExpectedFileIsSymlink(path));
    }
    if !metadata.is_file() {
        return Ok(None);
    }

    let text = fs::read_to_string(path)?;
    Ok(Some(BuildInfo::parse(&text)))
}

fn validate_package_manifest(
    root: &Path,
    executables: &[TargetExecutable],
) -> Result<PackageManifestStatus, TargetError> {
    let path = root.join("SHA256SUMS.txt");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(PackageManifestStatus::Absent);
        }
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() {
        return Err(TargetError::ExpectedFileIsSymlink(path));
    }
    if !metadata.is_file() {
        return Ok(PackageManifestStatus::Invalid(
            "SHA256SUMS.txt is not a regular file".to_owned(),
        ));
    }

    let text = fs::read_to_string(path)?;
    let mut manifest = BTreeMap::new();
    for (line_number, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let Some((hash, name)) = line.split_once("  ") else {
            return Ok(PackageManifestStatus::Invalid(format!(
                "malformed checksum line {}",
                line_number + 1
            )));
        };
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Ok(PackageManifestStatus::Invalid(format!(
                "invalid checksum on line {}",
                line_number + 1
            )));
        }
        if manifest
            .insert(name.to_ascii_lowercase(), hash.to_ascii_lowercase())
            .is_some()
        {
            return Ok(PackageManifestStatus::Invalid(format!(
                "duplicate manifest entry: {name}"
            )));
        }
    }

    for executable in executables {
        let key = executable.name.to_ascii_lowercase();
        let Some(expected) = manifest.get(&key) else {
            return Ok(PackageManifestStatus::Invalid(format!(
                "manifest is missing {}",
                executable.name
            )));
        };
        if expected != &executable.sha256 {
            return Ok(PackageManifestStatus::Invalid(format!(
                "checksum mismatch for {}",
                executable.name
            )));
        }
    }

    Ok(PackageManifestStatus::Valid)
}

fn build_fingerprint(executables: &[TargetExecutable]) -> String {
    let mut hasher = Sha256::new();
    for executable in executables {
        hasher.update(executable.name.as_bytes());
        hasher.update(&[0]);
        hasher.update(executable.sha256.as_bytes());
        hasher.update(&[0]);
        hasher.update(executable.size_bytes.to_string().as_bytes());
        hasher.update(b"\n");
    }
    hex_digest(&hasher.finalize())
}

fn write_optional_json(output: &mut String, key: &str, value: Option<&str>, comma: bool) {
    let suffix = if comma { "," } else { "" };
    match value {
        Some(value) => {
            let _ = writeln!(
                output,
                "    \"{}\": \"{}\"{suffix}",
                json_escape(key),
                json_escape(value)
            );
        }
        None => {
            let _ = writeln!(output, "    \"{}\": null{suffix}", json_escape(key));
        }
    }
}

fn write_string_array(output: &mut String, key: &str, values: &[String], comma: bool) {
    let suffix = if comma { "," } else { "" };
    let _ = writeln!(output, "  \"{}\": [", json_escape(key));
    for (index, value) in values.iter().enumerate() {
        let item_comma = if index + 1 == values.len() { "" } else { "," };
        let _ = writeln!(output, "    \"{}\"{item_comma}", json_escape(value));
    }
    let _ = writeln!(output, "  ]{suffix}");
}

fn json_escape(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            control if control.is_control() => {
                let _ = write!(output, "\\u{:04x}", u32::from(control));
            }
            other => output.push(other),
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        EXPECTED_EXECUTABLES, PackageManifestStatus, TargetError, discover_candidates,
        inspect_target, resolve_target,
    };
    use crate::hash::{hex_digest, sha256_file};

    fn temp_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "dfstl-target-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn create_complete_target(root: &Path) {
        fs::create_dir_all(root).expect("create target");
        for (index, name) in EXPECTED_EXECUTABLES.iter().enumerate() {
            fs::write(root.join(name), format!("synthetic-executable-{index}"))
                .expect("write executable");
        }

        fs::write(
            root.join("BUILD-INFO.txt"),
            concat!(
                "DragonForge Security Suite\n",
                "Version: v9.9.9-test\n",
                "Release channel: test\n",
                "Git commit: 0123456789abcdef\n",
                "Git tag: v9.9.9-test\n",
                "Built (UTC): 2026-09-23T00:00:00Z\n",
                "Platform: Windows x64 portable\n",
                "Code signing: synthetic\n",
            ),
        )
        .expect("write build info");

        let mut manifest = String::new();
        let mut names = EXPECTED_EXECUTABLES.to_vec();
        names.sort();
        for name in names {
            let digest = hex_digest(&sha256_file(&root.join(name)).expect("hash executable"));
            manifest.push_str(&digest);
            manifest.push_str("  ");
            manifest.push_str(name);
            manifest.push('\n');
        }
        fs::write(root.join("SHA256SUMS.txt"), manifest).expect("write manifest");
    }

    #[test]
    fn complete_target_is_identified_and_manifest_is_valid() {
        let root = temp_root("complete");
        create_complete_target(&root);

        let inspection = inspect_target(&root).expect("inspect");
        assert!(inspection.complete);
        assert_eq!(inspection.executables.len(), EXPECTED_EXECUTABLES.len());
        assert!(inspection.missing_executables.is_empty());
        assert!(inspection.unexpected_dragonforge_executables.is_empty());
        assert_eq!(inspection.build_fingerprint.len(), 64);
        assert_eq!(inspection.manifest_status, PackageManifestStatus::Valid);

        let info = inspection.build_info.expect("build info");
        assert_eq!(info.version.as_deref(), Some("v9.9.9-test"));
        assert_eq!(info.git_commit.as_deref(), Some("0123456789abcdef"));
        assert!(info.has_identity_metadata());

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn missing_executable_marks_target_incomplete() {
        let root = temp_root("missing");
        create_complete_target(&root);
        fs::remove_file(root.join("dragonforge-agent.exe")).expect("remove executable");

        let inspection = inspect_target(&root).expect("inspect");
        assert!(!inspection.complete);
        assert_eq!(
            inspection.missing_executables,
            vec!["dragonforge-agent.exe".to_owned()]
        );

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn manifest_checksum_mismatch_is_reported() {
        let root = temp_root("manifest");
        create_complete_target(&root);
        fs::write(root.join("dragonforge-agent.exe"), b"tampered").expect("tamper");

        let inspection = inspect_target(&root).expect("inspect");
        assert!(matches!(
            inspection.manifest_status,
            PackageManifestStatus::Invalid(_)
        ));

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn unexpected_dragonforge_executable_is_reported() {
        let root = temp_root("unexpected");
        create_complete_target(&root);
        fs::write(root.join("dragonforge-future-tool.exe"), b"future").expect("write extra");

        let inspection = inspect_target(&root).expect("inspect");
        assert_eq!(
            inspection.unexpected_dragonforge_executables,
            vec!["dragonforge-future-tool.exe".to_owned()]
        );

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn exact_target_resolves_directly() {
        let root = temp_root("direct");
        create_complete_target(&root);

        assert_eq!(resolve_target(&root).expect("resolve"), root);

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn exactly_one_child_candidate_resolves() {
        let root = temp_root("one-child");
        let target = root.join("DragonForge-Security-Suite-test");
        create_complete_target(&target);

        assert_eq!(
            discover_candidates(&root).expect("discover"),
            vec![target.clone()]
        );
        assert_eq!(resolve_target(&root).expect("resolve"), target);

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn multiple_child_candidates_fail_closed_as_ambiguous() {
        let root = temp_root("ambiguous");
        create_complete_target(&root.join("build-a"));
        create_complete_target(&root.join("build-b"));

        let error = resolve_target(&root).expect_err("must be ambiguous");
        assert!(matches!(error, TargetError::AmbiguousCandidates(paths) if paths.len() == 2));

        fs::remove_dir_all(root).expect("cleanup");
    }
}
