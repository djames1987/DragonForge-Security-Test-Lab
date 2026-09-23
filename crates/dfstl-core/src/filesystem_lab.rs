use std::fmt;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Component, Path, PathBuf};
use crate::hash::{hex_digest, sha256_bytes};

pub const MAX_LAB_CASES: usize = 64;

#[derive(Debug)]
pub enum FilesystemLabError {
    Io(io::Error),
    RootExists(PathBuf),
    UnsafeRoot(PathBuf),
    RootIsSymlink(PathBuf),
}

impl fmt::Display for FilesystemLabError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => f.write_str("filesystem lab I/O failure"),
            Self::RootExists(path) => {
                write!(f, "filesystem lab root already exists: {}", path.display())
            }
            Self::UnsafeRoot(path) => {
                write!(f, "filesystem lab root is unsafe: {}", path.display())
            }
            Self::RootIsSymlink(path) => {
                write!(f, "filesystem lab root must not be a symlink: {}", path.display())
            }
        }
    }
}

impl std::error::Error for FilesystemLabError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for FilesystemLabError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabCaseStatus {
    Pass,
    Fail,
    Skipped,
}

impl LabCaseStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabCase {
    pub id: String,
    pub status: LabCaseStatus,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemLabReport {
    pub schema_version: u32,
    pub platform: String,
    pub lab_root: PathBuf,
    pub cases: Vec<LabCase>,
}

impl FilesystemLabReport {
    #[must_use]
    pub fn has_failures(&self) -> bool {
        self.cases
            .iter()
            .any(|case| matches!(case.status, LabCaseStatus::Fail))
    }

    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(output, "{{");
        let _ = writeln!(output, "  \"schema_version\": {},", self.schema_version);
        let _ = writeln!(
            output,
            "  \"platform\": \"{}\",",
            json_escape(&self.platform)
        );
        let _ = writeln!(
            output,
            "  \"lab_root\": \"{}\",",
            json_escape(&self.lab_root.to_string_lossy())
        );
        let _ = writeln!(output, "  \"has_failures\": {},", self.has_failures());
        let _ = writeln!(output, "  \"cases\": [");
        for (index, case) in self.cases.iter().enumerate() {
            let comma = if index + 1 == self.cases.len() {
                ""
            } else {
                ","
            };
            let _ = writeln!(output, "    {{");
            let _ = writeln!(output, "      \"id\": \"{}\",", json_escape(&case.id));
            let _ = writeln!(
                output,
                "      \"status\": \"{}\",",
                case.status.as_str()
            );
            let _ = writeln!(
                output,
                "      \"detail\": \"{}\"",
                json_escape(&case.detail)
            );
            let _ = writeln!(output, "    }}{comma}");
        }
        let _ = writeln!(output, "  ]");
        let _ = writeln!(output, "}}");
        output
    }

    #[must_use]
    pub fn to_text(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(output, "DragonForge filesystem lab");
        let _ = writeln!(output, "Platform: {}", self.platform);
        let _ = writeln!(output, "Lab root: {}", self.lab_root.display());
        for case in &self.cases {
            let _ = writeln!(
                output,
                "{}  {}  {}",
                case.id,
                case.status.as_str(),
                case.detail
            );
        }
        output
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathCorpusCase {
    pub id: String,
    pub value: String,
    pub expected_safe: bool,
    pub accepted: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathCorpusReport {
    pub schema_version: u32,
    pub cases: Vec<PathCorpusCase>,
}

impl PathCorpusReport {
    #[must_use]
    pub fn all_expected(&self) -> bool {
        self.cases
            .iter()
            .all(|case| case.expected_safe == case.accepted)
    }

    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(output, "{{");
        let _ = writeln!(output, "  \"schema_version\": {},", self.schema_version);
        let _ = writeln!(output, "  \"all_expected\": {},", self.all_expected());
        let _ = writeln!(output, "  \"cases\": [");
        for (index, case) in self.cases.iter().enumerate() {
            let comma = if index + 1 == self.cases.len() {
                ""
            } else {
                ","
            };
            let _ = writeln!(
                output,
                concat!(
                    "    {{\"id\":\"{}\",\"value\":\"{}\",",
                    "\"expected_safe\":{},\"accepted\":{},\"reason\":\"{}\"}}{comma}"
                ),
                json_escape(&case.id),
                json_escape(&case.value),
                case.expected_safe,
                case.accepted,
                json_escape(&case.reason)
            );
        }
        let _ = writeln!(output, "  ]");
        let _ = writeln!(output, "}}");
        output
    }
}

/// Generates the deterministic path-policy regression corpus used by Phase 6.
#[must_use]
pub fn path_policy_corpus() -> PathCorpusReport {
    let inputs = [
        ("normal", "folder/file.txt", true),
        ("nested-unicode", "世界/naïve.txt", true),
        ("dot", "./file.txt", false),
        ("dotdot", "../escape.txt", false),
        ("nested-dotdot", "safe/../escape.txt", false),
        ("absolute-root", "/absolute.txt", false),
        ("backslash", r"safe\..\escape.txt", false),
        ("drive-prefix", r"C:\Windows\win.ini", false),
        ("unc-prefix", r"\\server\share\file", false),
        ("alternate-stream", "file.txt:stream", false),
        ("nul", "NUL", false),
        ("con-extension", "CON.txt", false),
        ("com1", "COM1.log", false),
        ("lpt9", "LPT9", false),
        ("trailing-dot", "folder/name.", false),
        ("trailing-space", "folder/name ", false),
        ("double-separator", "folder//file.txt", false),
        ("empty", "", false),
        ("control", "folder/line\nfeed", false),
        ("dot-segment", "folder/./file", false),
        ("safe-hyphen", "folder/safe-name_01.bin", true),
        ("decomposed-unicode", "folder/e\u{301}.txt", true),
    ];

    let cases = inputs
        .into_iter()
        .map(|(id, value, expected_safe)| {
            let result = validate_windows_relative_path(value);
            PathCorpusCase {
                id: id.to_owned(),
                value: value.to_owned(),
                expected_safe,
                accepted: result.is_ok(),
                reason: result.err().unwrap_or_else(|| "accepted".to_owned()),
            }
        })
        .collect();

    PathCorpusReport {
        schema_version: 1,
        cases,
    }
}

/// Validates an archive/restore path against Windows-safe containment rules.
///
/// The policy intentionally rejects Windows device names, drive/UNC syntax,
/// traversal, alternate-data-stream syntax, backslashes, controls, and
/// trailing dots/spaces.
///
/// # Errors
///
/// Returns a stable explanatory string when the path is unsafe.
pub fn validate_windows_relative_path(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("empty path".to_owned());
    }
    if value.contains('\0') {
        return Err("NUL byte".to_owned());
    }
    if value.contains('\\') {
        return Err("backslash separator".to_owned());
    }
    if value.starts_with('/') || value.starts_with("//") {
        return Err("absolute or UNC-like path".to_owned());
    }
    if value.contains(':') {
        return Err("drive or alternate-stream colon".to_owned());
    }

    let path = Path::new(value);
    if path.is_absolute() {
        return Err("absolute path".to_owned());
    }

    let mut count = 0_usize;
    for component in path.components() {
        let Component::Normal(segment) = component else {
            return Err("non-normal path component".to_owned());
        };
        let segment = segment
            .to_str()
            .ok_or_else(|| "non-Unicode path segment".to_owned())?;
        validate_windows_segment(segment)?;
        count += 1;
    }

    if count == 0 || value.split('/').any(str::is_empty) {
        return Err("empty path component".to_owned());
    }
    Ok(())
}

fn validate_windows_segment(segment: &str) -> Result<(), String> {
    if segment.is_empty() || segment == "." || segment == ".." {
        return Err("dot or empty segment".to_owned());
    }
    if segment.chars().any(char::is_control) {
        return Err("control character".to_owned());
    }
    if segment.ends_with('.') || segment.ends_with(' ') {
        return Err("trailing dot or space".to_owned());
    }
    if segment
        .chars()
        .any(|character| matches!(character, '<' | '>' | '"' | '|' | '?' | '*'))
    {
        return Err("Windows-reserved character".to_owned());
    }

    let trimmed = segment.trim_end_matches(['.', ' ']);
    let stem = trimmed
        .split('.')
        .next()
        .unwrap_or(trimmed)
        .to_ascii_uppercase();
    if is_windows_device_name(&stem) {
        return Err("Windows reserved device name".to_owned());
    }
    Ok(())
}

fn is_windows_device_name(stem: &str) -> bool {
    matches!(stem, "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$")
        || matches!(
            stem,
            "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        )
}

/// Runs the disposable LabOnly filesystem test matrix under one new explicit root.
///
/// The root must not already exist. The harness never operates outside that root.
///
/// # Errors
///
/// Returns an error when the root is unsafe or filesystem setup fails before
/// individual cases can be recorded.
pub fn run_filesystem_lab(root: &Path) -> Result<FilesystemLabReport, FilesystemLabError> {
    validate_new_lab_root(root)?;
    fs::create_dir(root)?;

    let result = run_lab_cases(root);
    if result.is_err() {
        let _ = fs::remove_dir_all(root);
    }
    result
}

fn run_lab_cases(root: &Path) -> Result<FilesystemLabReport, FilesystemLabError> {
    let mut cases = Vec::new();

    cases.push(path_policy_case());
    cases.push(containment_case(root)?);
    cases.push(destination_race_case(root)?);
    cases.push(hard_link_case(root)?);
    cases.push(source_replacement_case(root)?);
    cases.extend(platform_reparse_cases(root)?);

    if cases.len() > MAX_LAB_CASES {
        cases.truncate(MAX_LAB_CASES);
    }

    let report = FilesystemLabReport {
        schema_version: 1,
        platform: std::env::consts::OS.to_owned(),
        lab_root: root.to_path_buf(),
        cases,
    };
    fs::write(root.join("filesystem-lab.json"), report.to_json_pretty())?;
    fs::write(root.join("filesystem-lab.txt"), report.to_text())?;
    write_manifest(root)?;
    Ok(report)
}

fn validate_new_lab_root(root: &Path) -> Result<(), FilesystemLabError> {
    if root.exists() {
        let metadata = fs::symlink_metadata(root)?;
        if metadata.file_type().is_symlink() {
            return Err(FilesystemLabError::RootIsSymlink(root.to_path_buf()));
        }
        return Err(FilesystemLabError::RootExists(root.to_path_buf()));
    }

    let absolute = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()?.join(root)
    };
    let depth = absolute.components().count();
    if depth < 3 || absolute.parent().is_none() {
        return Err(FilesystemLabError::UnsafeRoot(root.to_path_buf()));
    }
    Ok(())
}

fn path_policy_case() -> LabCase {
    let corpus = path_policy_corpus();
    LabCase {
        id: "path-policy-corpus".to_owned(),
        status: if corpus.all_expected() {
            LabCaseStatus::Pass
        } else {
            LabCaseStatus::Fail
        },
        detail: format!(
            "{} deterministic Windows path-policy cases matched expectations",
            corpus.cases.len()
        ),
    }
}

fn containment_case(root: &Path) -> Result<LabCase, FilesystemLabError> {
    let staging = root.join("containment").join("staging");
    fs::create_dir_all(&staging)?;
    let safe = "nested/file.txt";
    validate_windows_relative_path(safe).map_err(|_| {
        FilesystemLabError::UnsafeRoot(root.to_path_buf())
    })?;
    let target = staging.join(safe);
    fs::create_dir_all(target.parent().unwrap_or(&staging))?;
    fs::write(&target, b"contained")?;

    let canonical_stage = fs::canonicalize(&staging)?;
    let canonical_target = fs::canonicalize(&target)?;
    let contained = canonical_target.starts_with(&canonical_stage);

    Ok(LabCase {
        id: "restore-containment".to_owned(),
        status: if contained {
            LabCaseStatus::Pass
        } else {
            LabCaseStatus::Fail
        },
        detail: "joined restore target remained below the canonical staging root".to_owned(),
    })
}

fn destination_race_case(root: &Path) -> Result<LabCase, FilesystemLabError> {
    let dir = root.join("destination-race");
    fs::create_dir_all(&dir)?;
    let target = dir.join("destination.txt");
    let precheck_absent = !target.exists();

    fs::write(&target, b"attacker-won-race")?;
    let create_new_rejected = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)
        .is_err();

    Ok(LabCase {
        id: "destination-create-new-race".to_owned(),
        status: if precheck_absent && create_new_rejected {
            LabCaseStatus::Pass
        } else {
            LabCaseStatus::Fail
        },
        detail: "create_new rejected a destination introduced after the absence check".to_owned(),
    })
}

fn hard_link_case(root: &Path) -> Result<LabCase, FilesystemLabError> {
    let dir = root.join("hard-link");
    fs::create_dir_all(&dir)?;
    let original = dir.join("original.txt");
    let alias = dir.join("alias.txt");
    fs::write(&original, b"sentinel")?;

    match fs::hard_link(&original, &alias) {
        Ok(()) => {
            fs::write(&alias, b"mutated")?;
            let same_content = fs::read(&original)? == b"mutated";
            Ok(LabCase {
                id: "hard-link-alias".to_owned(),
                status: if same_content {
                    LabCaseStatus::Pass
                } else {
                    LabCaseStatus::Fail
                },
                detail: "hard-link alias demonstrated shared underlying file identity".to_owned(),
            })
        }
        Err(error) => Ok(LabCase {
            id: "hard-link-alias".to_owned(),
            status: LabCaseStatus::Skipped,
            detail: format!("hard-link creation unavailable: {error}"),
        }),
    }
}

fn source_replacement_case(root: &Path) -> Result<LabCase, FilesystemLabError> {
    let dir = root.join("source-race");
    fs::create_dir_all(&dir)?;
    let source = dir.join("source.txt");
    fs::write(&source, b"before")?;
    let metadata_before = fs::metadata(&source)?;
    let length_before = metadata_before.len();

    fs::remove_file(&source)?;
    fs::write(&source, b"replacement-content")?;
    let length_after = fs::metadata(&source)?.len();

    Ok(LabCase {
        id: "source-replacement-race".to_owned(),
        status: if length_before != length_after {
            LabCaseStatus::Pass
        } else {
            LabCaseStatus::Fail
        },
        detail: "disposable source was replaced between metadata observation and later read".to_owned(),
    })
}

#[cfg(windows)]
fn platform_reparse_cases(root: &Path) -> Result<Vec<LabCase>, FilesystemLabError> {
    use std::os::windows::fs::{symlink_dir, symlink_file};

    let dir = root.join("reparse");
    fs::create_dir_all(&dir)?;
    let target_dir = dir.join("real-dir");
    fs::create_dir(&target_dir)?;
    let target_file = dir.join("real-file.txt");
    fs::write(&target_file, b"real")?;

    let dir_link = dir.join("dir-link");
    let file_link = dir.join("file-link.txt");

    let directory_case = match symlink_dir(&target_dir, &dir_link) {
        Ok(()) => {
            let meta = fs::symlink_metadata(&dir_link)?;
            LabCase {
                id: "directory-reparse-link".to_owned(),
                status: if meta.file_type().is_symlink() {
                    LabCaseStatus::Pass
                } else {
                    LabCaseStatus::Fail
                },
                detail: "directory reparse link was created and detectable by symlink_metadata"
                    .to_owned(),
            }
        }
        Err(error) => LabCase {
            id: "directory-reparse-link".to_owned(),
            status: LabCaseStatus::Skipped,
            detail: format!("directory reparse creation unavailable: {error}"),
        },
    };

    let file_case = match symlink_file(&target_file, &file_link) {
        Ok(()) => {
            let meta = fs::symlink_metadata(&file_link)?;
            LabCase {
                id: "file-reparse-link".to_owned(),
                status: if meta.file_type().is_symlink() {
                    LabCaseStatus::Pass
                } else {
                    LabCaseStatus::Fail
                },
                detail: "file reparse link was created and detectable by symlink_metadata"
                    .to_owned(),
            }
        }
        Err(error) => LabCase {
            id: "file-reparse-link".to_owned(),
            status: LabCaseStatus::Skipped,
            detail: format!("file reparse creation unavailable: {error}"),
        },
    };

    Ok(vec![directory_case, file_case])
}

#[cfg(not(windows))]
fn platform_reparse_cases(_root: &Path) -> Result<Vec<LabCase>, FilesystemLabError> {
    Ok(vec![LabCase {
        id: "windows-reparse-links".to_owned(),
        status: LabCaseStatus::Skipped,
        detail: "Windows reparse-point creation is only executed on Windows".to_owned(),
    }])
}

fn write_manifest(root: &Path) -> Result<(), FilesystemLabError> {
    let mut entries = Vec::new();
    collect_regular_files(root, root, &mut entries)?;
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let mut manifest = String::new();
    for (relative, bytes) in entries {
        if relative == "SHA256SUMS" {
            continue;
        }
        let _ = writeln!(
            manifest,
            "{}  {}",
            hex_digest(&sha256_bytes(&bytes)),
            relative
        );
    }
    fs::write(root.join("SHA256SUMS"), manifest)?;
    Ok(())
}

fn collect_regular_files(
    root: &Path,
    current: &Path,
    entries: &mut Vec<(String, Vec<u8>)>,
) -> Result<(), FilesystemLabError> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            collect_regular_files(root, &path, entries)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            entries.push((relative, fs::read(&path)?));
        }
    }
    Ok(())
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
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{path_policy_corpus, run_filesystem_lab, validate_windows_relative_path};

    fn temp_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "dfstl-fs-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn deterministic_path_corpus_matches_expected_policy() {
        let report = path_policy_corpus();
        assert!(report.all_expected());
        assert_eq!(report.cases.len(), 22);
    }

    #[test]
    fn reserved_windows_names_are_rejected_case_insensitively() {
        for value in ["CON", "con.txt", "Aux", "Lpt1.log", "COM9"] {
            assert!(validate_windows_relative_path(value).is_err(), "{value}");
        }
    }

    #[test]
    fn valid_unicode_relative_paths_are_accepted() {
        assert!(validate_windows_relative_path("世界/naïve.txt").is_ok());
        assert!(validate_windows_relative_path("folder/e\u{301}.txt").is_ok());
    }

    #[test]
    fn lab_root_must_be_new() {
        let root = temp_root("existing");
        fs::create_dir(&root).expect("root");
        assert!(run_filesystem_lab(&root).is_err());
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn disposable_lab_exercises_containment_and_races() {
        let root = temp_root("matrix");
        let report = run_filesystem_lab(&root).expect("lab");
        assert!(!report.has_failures());
        assert!(
            report
                .cases
                .iter()
                .any(|case| case.id == "hard-link-alias")
        );
        assert!(
            report
                .cases
                .iter()
                .any(|case| case.id == "destination-create-new-race")
        );
        assert!(root.join("SHA256SUMS").is_file());
        fs::remove_dir_all(root).expect("cleanup");
    }
}
