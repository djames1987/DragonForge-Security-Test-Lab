use std::fmt;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};

use crate::hash::{hex_digest, sha256_bytes};

pub const MAX_SENTINELS: usize = 64;
pub const MAX_SENTINEL_BYTES: usize = 512;
pub const MAX_SCAN_FILES: usize = 4096;
pub const MAX_FILE_SCAN_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_TOTAL_SCAN_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_DUMP_SCAN_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug)]
pub enum SecretLeakError {
    Io(io::Error),
    InvalidSentinelLine(usize),
    InvalidSentinelId(usize),
    InvalidSentinelLength(usize),
    TooManySentinels,
    NoSentinels,
    RootMissing(PathBuf),
    RootIsSymlink(PathBuf),
    ScanLimitExceeded,
    OutputExists(PathBuf),
}

impl fmt::Display for SecretLeakError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => f.write_str("secret-leak scanner I/O failure"),
            Self::InvalidSentinelLine(line) => write!(f, "invalid sentinel definition on line {line}"),
            Self::InvalidSentinelId(line) => write!(f, "invalid sentinel ID on line {line}"),
            Self::InvalidSentinelLength(line) => {
                write!(f, "invalid sentinel value length on line {line}")
            }
            Self::TooManySentinels => f.write_str("too many synthetic sentinel definitions"),
            Self::NoSentinels => f.write_str("no synthetic sentinel definitions were provided"),
            Self::RootMissing(path) => write!(f, "scan root does not exist: {}", path.display()),
            Self::RootIsSymlink(path) => {
                write!(f, "scan root must not be a symlink: {}", path.display())
            }
            Self::ScanLimitExceeded => f.write_str("secret-leak scan exceeded its safety budget"),
            Self::OutputExists(path) => {
                write!(f, "secret-leak evidence output already exists: {}", path.display())
            }
        }
    }
}

impl std::error::Error for SecretLeakError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for SecretLeakError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub struct SecretSentinel {
    id: String,
    value: Vec<u8>,
}

impl SecretSentinel {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl fmt::Debug for SecretSentinel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretSentinel")
            .field("id", &self.id)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SecretSentinel {
    fn drop(&mut self) {
        self.value.fill(0);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakFinding {
    pub sentinel_id: String,
    pub relative_path: String,
    pub representation: String,
    pub offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretLeakReport {
    pub schema_version: u32,
    pub scope: String,
    pub roots_scanned: usize,
    pub files_scanned: usize,
    pub bytes_scanned: u64,
    pub skipped_oversized_files: usize,
    pub findings: Vec<LeakFinding>,
}

impl SecretLeakReport {
    #[must_use]
    pub fn clean(&self) -> bool {
        self.findings.is_empty()
    }

    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(output, "{{");
        let _ = writeln!(output, "  \"schema_version\": {},", self.schema_version);
        let _ = writeln!(output, "  \"scope\": \"{}\",", json_escape(&self.scope));
        let _ = writeln!(output, "  \"roots_scanned\": {},", self.roots_scanned);
        let _ = writeln!(output, "  \"files_scanned\": {},", self.files_scanned);
        let _ = writeln!(output, "  \"bytes_scanned\": {},", self.bytes_scanned);
        let _ = writeln!(
            output,
            "  \"skipped_oversized_files\": {},",
            self.skipped_oversized_files
        );
        let _ = writeln!(output, "  \"clean\": {},", self.clean());
        let _ = writeln!(output, "  \"findings\": [");
        for (index, finding) in self.findings.iter().enumerate() {
            let comma = if index + 1 == self.findings.len() {
                ""
            } else {
                ","
            };
            let _ = writeln!(
                output,
                concat!(
                    "    {{\"sentinel_id\":\"{}\",\"relative_path\":\"{}\",",
                    "\"representation\":\"{}\",\"offset\":{}}}{}"
                ),
                json_escape(&finding.sentinel_id),
                json_escape(&finding.relative_path),
                json_escape(&finding.representation),
                finding.offset,
                comma
            );
        }
        let _ = writeln!(output, "  ]");
        let _ = writeln!(output, "}}");
        output
    }

    #[must_use]
    pub fn to_text(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(output, "DragonForge Secret Leak Scan");
        let _ = writeln!(output, "Scope: {}", self.scope);
        let _ = writeln!(output, "Roots: {}", self.roots_scanned);
        let _ = writeln!(output, "Files: {}", self.files_scanned);
        let _ = writeln!(output, "Bytes: {}", self.bytes_scanned);
        let _ = writeln!(output, "Oversized skipped: {}", self.skipped_oversized_files);
        let _ = writeln!(output, "Findings: {}", self.findings.len());
        for finding in &self.findings {
            let _ = writeln!(
                output,
                "{}  {}  {}  offset={}",
                finding.sentinel_id,
                finding.relative_path,
                finding.representation,
                finding.offset
            );
        }
        output
    }
}

/// Loads synthetic sentinel secrets from a line-oriented file.
///
/// Format: one ID=value pair per non-empty, non-comment line.
///
/// # Errors
///
/// Returns an error for malformed definitions or I/O failures.
pub fn load_sentinels(path: &Path) -> Result<Vec<SecretSentinel>, SecretLeakError> {
    let content = fs::read_to_string(path)?;
    let mut sentinels = Vec::new();
    for (index, raw_line) in content.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if sentinels.len() >= MAX_SENTINELS {
            return Err(SecretLeakError::TooManySentinels);
        }
        let (id, value) = line
            .split_once('=')
            .ok_or(SecretLeakError::InvalidSentinelLine(line_number))?;
        if id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(SecretLeakError::InvalidSentinelId(line_number));
        }
        if value.len() < 12 || value.len() > MAX_SENTINEL_BYTES || !value.is_ascii() {
            return Err(SecretLeakError::InvalidSentinelLength(line_number));
        }
        sentinels.push(SecretSentinel {
            id: id.to_owned(),
            value: value.as_bytes().to_vec(),
        });
    }
    if sentinels.is_empty() {
        return Err(SecretLeakError::NoSentinels);
    }
    Ok(sentinels)
}

/// Scans explicit artifact roots for synthetic sentinel secrets.
///
/// Symlink roots and symlink entries are not followed.
///
/// # Errors
///
/// Returns an error for missing roots, unsafe roots, I/O errors, or scan-budget exhaustion.
pub fn scan_artifact_roots(
    roots: &[PathBuf],
    sentinels: &[SecretSentinel],
) -> Result<SecretLeakReport, SecretLeakError> {
    let mut state = ScanState::new("artifact-tree", roots.len());
    for root in roots {
        let metadata = fs::symlink_metadata(root).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                SecretLeakError::RootMissing(root.clone())
            } else {
                SecretLeakError::Io(error)
            }
        })?;
        if metadata.file_type().is_symlink() {
            return Err(SecretLeakError::RootIsSymlink(root.clone()));
        }
        if metadata.is_file() {
            scan_one_file(root, root, sentinels, &mut state)?;
        } else if metadata.is_dir() {
            let canonical_root = fs::canonicalize(root)?;
            scan_directory(
                root,
                &canonical_root,
                root,
                sentinels,
                &mut state,
            )?;
        }
    }
    Ok(state.finish())
}

/// Scans one explicit process-dump file for synthetic sentinel secrets.
///
/// The dump is read-only and is never copied into DFSTL evidence.
///
/// # Errors
///
/// Returns an error for missing files, symlinks, I/O errors, or scan-budget exhaustion.
pub fn scan_process_dump(
    dump_path: &Path,
    sentinels: &[SecretSentinel],
) -> Result<SecretLeakReport, SecretLeakError> {
    let metadata = fs::symlink_metadata(dump_path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            SecretLeakError::RootMissing(dump_path.to_path_buf())
        } else {
            SecretLeakError::Io(error)
        }
    })?;
    if metadata.file_type().is_symlink() {
        return Err(SecretLeakError::RootIsSymlink(dump_path.to_path_buf()));
    }

    if metadata.len() > MAX_DUMP_SCAN_BYTES {
        return Err(SecretLeakError::ScanLimitExceeded);
    }

    let mut state = ScanState::new("process-dump", 1);
    scan_dump_file(dump_path, sentinels, &mut state)?;
    Ok(state.finish())
}

/// Writes redaction-safe scan evidence and a SHA-256 manifest.
///
/// # Errors
///
/// Returns an error when the output already exists or evidence cannot be written.
pub fn write_secret_leak_bundle(
    output_dir: &Path,
    report: &SecretLeakReport,
) -> Result<(), SecretLeakError> {
    if output_dir.exists() {
        return Err(SecretLeakError::OutputExists(output_dir.to_path_buf()));
    }
    fs::create_dir(output_dir)?;
    fs::write(output_dir.join("secret-leak.json"), report.to_json_pretty())?;
    fs::write(output_dir.join("secret-leak.txt"), report.to_text())?;

    let mut manifest = String::new();
    for name in ["secret-leak.json", "secret-leak.txt"] {
        let bytes = fs::read(output_dir.join(name))?;
        let _ = writeln!(manifest, "{}  {name}", hex_digest(&sha256_bytes(&bytes)));
    }
    fs::write(output_dir.join("SHA256SUMS"), manifest)?;
    Ok(())
}

/// Executes a synthetic in-memory secret lifecycle check.
///
/// The function confirms the sentinel is present, overwrites its buffer with
/// zero bytes, and verifies the same allocation no longer contains the sentinel.
#[must_use]
pub fn synthetic_memory_lifecycle_check() -> bool {
    let marker = b"DFSTL-PHASE9-SYNTHETIC-MEMORY-SECRET";
    let mut buffer = marker.to_vec();
    let present_before = contains_bytes(&buffer, marker);
    buffer.fill(0);
    present_before && !contains_bytes(&buffer, marker) && buffer.iter().all(|byte| *byte == 0)
}

fn scan_directory(
    root: &Path,
    canonical_root: &Path,
    current: &Path,
    sentinels: &[SecretSentinel],
    state: &mut ScanState,
) -> Result<(), SecretLeakError> {
    let canonical_current = fs::canonicalize(current)?;
    if !canonical_current.starts_with(canonical_root) {
        return Ok(());
    }
    if state.visited_directories.contains(&canonical_current) {
        return Ok(());
    }
    state.visited_directories.push(canonical_current);

    let mut entries = fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);

    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            continue;
        }

        let canonical_path = fs::canonicalize(&path)?;
        if !canonical_path.starts_with(canonical_root) {
            continue;
        }

        if metadata.is_dir() {
            scan_directory(root, canonical_root, &path, sentinels, state)?;
        } else if metadata.is_file() {
            scan_one_file(root, &path, sentinels, state)?;
        }
    }
    Ok(())
}

fn scan_dump_file(
    path: &Path,
    sentinels: &[SecretSentinel],
    state: &mut ScanState,
) -> Result<(), SecretLeakError> {
    const CHUNK_BYTES: usize = 1024 * 1024;

    let file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    let variants = sentinels
        .iter()
        .flat_map(|sentinel| {
            sentinel_variants(sentinel)
                .into_iter()
                .map(move |variant| (sentinel.id.clone(), variant))
        })
        .collect::<Vec<_>>();
    let max_pattern = variants
        .iter()
        .map(|(_, variant)| variant.bytes.len())
        .max()
        .unwrap_or(1);
    let overlap_size = max_pattern.saturating_sub(1);
    let mut reader = BufReader::new(file);
    let mut buffer = vec![0_u8; CHUNK_BYTES];
    let mut overlap = Vec::new();
    let mut total_read = 0_u64;

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let chunk_start = total_read;
        total_read = total_read.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
        if total_read > MAX_DUMP_SCAN_BYTES {
            return Err(SecretLeakError::ScanLimitExceeded);
        }

        let mut window = Vec::with_capacity(overlap.len() + count);
        window.extend_from_slice(&overlap);
        window.extend_from_slice(&buffer[..count]);
        let base_offset = chunk_start.saturating_sub(
            u64::try_from(overlap.len()).unwrap_or(u64::MAX),
        );

        for (sentinel_id, variant) in &variants {
            for offset in find_all(&window, &variant.bytes) {
                let absolute = base_offset.saturating_add(
                    u64::try_from(offset).unwrap_or(u64::MAX),
                );
                if absolute.saturating_add(
                    u64::try_from(variant.bytes.len()).unwrap_or(u64::MAX),
                ) <= chunk_start
                {
                    continue;
                }
                state.findings.push(LeakFinding {
                    sentinel_id: sentinel_id.clone(),
                    relative_path: path
                        .file_name()
                        .map_or_else(
                            || "process.dmp".to_owned(),
                            |name| name.to_string_lossy().into_owned(),
                        ),
                    representation: variant.label.to_owned(),
                    offset: usize::try_from(absolute).unwrap_or(usize::MAX),
                });
            }
        }

        let keep = overlap_size.min(window.len());
        overlap.clear();
        overlap.extend_from_slice(&window[window.len() - keep..]);
    }

    state.files_scanned = 1;
    state.bytes_scanned = metadata.len();
    Ok(())
}

fn scan_one_file(
    root: &Path,
    path: &Path,
    sentinels: &[SecretSentinel],
    state: &mut ScanState,
) -> Result<(), SecretLeakError> {
    if state.files_scanned >= MAX_SCAN_FILES {
        return Err(SecretLeakError::ScanLimitExceeded);
    }

    let metadata = fs::metadata(path)?;
    if metadata.len() > u64::try_from(MAX_FILE_SCAN_BYTES).unwrap_or(u64::MAX) {
        state.skipped_oversized_files += 1;
        return Ok(());
    }
    if state
        .bytes_scanned
        .saturating_add(metadata.len())
        > u64::try_from(MAX_TOTAL_SCAN_BYTES).unwrap_or(u64::MAX)
    {
        return Err(SecretLeakError::ScanLimitExceeded);
    }

    let bytes = fs::read(path)?;
    state.files_scanned += 1;
    state.bytes_scanned = state
        .bytes_scanned
        .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
    let relative_path = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    let display_path = if relative_path.is_empty() {
        path.file_name()
            .map_or_else(|| ".".to_owned(), |name| name.to_string_lossy().into_owned())
    } else {
        relative_path
    };

    for sentinel in sentinels {
        for variant in sentinel_variants(sentinel) {
            for offset in find_all(&bytes, &variant.bytes) {
                state.findings.push(LeakFinding {
                    sentinel_id: sentinel.id.clone(),
                    relative_path: display_path.clone(),
                    representation: variant.label.to_owned(),
                    offset,
                });
            }
        }
    }
    Ok(())
}

struct SentinelVariant {
    label: &'static str,
    bytes: Vec<u8>,
}

fn sentinel_variants(sentinel: &SecretSentinel) -> [SentinelVariant; 4] {
    [
        SentinelVariant {
            label: "raw",
            bytes: sentinel.value.clone(),
        },
        SentinelVariant {
            label: "hex-lower",
            bytes: hex_encode(&sentinel.value).into_bytes(),
        },
        SentinelVariant {
            label: "base64",
            bytes: base64_encode(&sentinel.value).into_bytes(),
        },
        SentinelVariant {
            label: "utf16le",
            bytes: utf16le_ascii(&sentinel.value),
        },
    ]
}

fn utf16le_ascii(bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(*byte);
        output.push(0);
    }
    output
}

fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return Vec::new();
    }
    haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(|(index, window)| (window == needle).then_some(index))
        .collect()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack.windows(needle.len()).any(|window| window == needle)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = u32::from(chunk[0]);
        let second = chunk.get(1).map_or(0, |value| u32::from(*value));
        let third = chunk.get(2).map_or(0, |value| u32::from(*value));
        let value = (first << 16) | (second << 8) | third;

        output.push(char::from(
            TABLE[usize::try_from((value >> 18) & 0x3f).unwrap_or(0)],
        ));
        output.push(char::from(
            TABLE[usize::try_from((value >> 12) & 0x3f).unwrap_or(0)],
        ));
        if chunk.len() > 1 {
            output.push(char::from(
                TABLE[usize::try_from((value >> 6) & 0x3f).unwrap_or(0)],
            ));
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(char::from(
                TABLE[usize::try_from(value & 0x3f).unwrap_or(0)],
            ));
        } else {
            output.push('=');
        }
    }
    output
}

struct ScanState {
    scope: &'static str,
    roots_scanned: usize,
    files_scanned: usize,
    bytes_scanned: u64,
    skipped_oversized_files: usize,
    findings: Vec<LeakFinding>,
    visited_directories: Vec<PathBuf>,
}

impl ScanState {
    fn new(scope: &'static str, roots_scanned: usize) -> Self {
        Self {
            scope,
            roots_scanned,
            files_scanned: 0,
            bytes_scanned: 0,
            skipped_oversized_files: 0,
            findings: Vec::new(),
            visited_directories: Vec::new(),
        }
    }

    fn finish(self) -> SecretLeakReport {
        SecretLeakReport {
            schema_version: 1,
            scope: self.scope.to_owned(),
            roots_scanned: self.roots_scanned,
            files_scanned: self.files_scanned,
            bytes_scanned: self.bytes_scanned,
            skipped_oversized_files: self.skipped_oversized_files,
            findings: self.findings,
        }
    }
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

    use super::{
        load_sentinels, scan_artifact_roots, scan_process_dump, synthetic_memory_lifecycle_check,
        write_secret_leak_bundle,
    };

    fn temp_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "dfstl-secret-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn scanner_finds_raw_hex_and_base64_without_emitting_secret_value() {
        let root = temp_path("scan");
        let sentinels_path = temp_path("sentinels");
        fs::create_dir(&root).expect("root");
        fs::write(
            &sentinels_path,
            "sync-token=DFSTL-SYNTHETIC-TOKEN-1234567890\n",
        )
        .expect("sentinels");
        let sentinels = load_sentinels(&sentinels_path).expect("load");
        let value = b"DFSTL-SYNTHETIC-TOKEN-1234567890";
        fs::write(root.join("raw.log"), value).expect("raw");
        fs::write(root.join("hex.log"), super::hex_encode(value)).expect("hex");
        fs::write(root.join("base64.log"), super::base64_encode(value)).expect("base64");

        let report = scan_artifact_roots(&[root.clone()], &sentinels).expect("scan");
        assert_eq!(report.findings.len(), 3);
        let json = report.to_json_pretty();
        assert!(!json.contains("DFSTL-SYNTHETIC-TOKEN-1234567890"));

        fs::remove_dir_all(root).expect("cleanup root");
        fs::remove_file(sentinels_path).expect("cleanup sentinels");
    }

    #[test]
    fn clean_artifact_tree_and_evidence_bundle_are_supported() {
        let root = temp_path("clean");
        let sentinels_path = temp_path("sentinels-clean");
        let output = temp_path("evidence");
        fs::create_dir(&root).expect("root");
        fs::write(&sentinels_path, "secret=DFSTL-NOT-PRESENT-1234567890\n").expect("sentinels");
        fs::write(root.join("safe.log"), "redacted diagnostic content").expect("safe");
        let sentinels = load_sentinels(&sentinels_path).expect("load");
        let report = scan_artifact_roots(&[root.clone()], &sentinels).expect("scan");
        assert!(report.clean());
        write_secret_leak_bundle(&output, &report).expect("evidence");
        assert!(output.join("SHA256SUMS").is_file());

        fs::remove_dir_all(root).expect("cleanup root");
        fs::remove_file(sentinels_path).expect("cleanup sentinels");
        fs::remove_dir_all(output).expect("cleanup output");
    }

    #[test]
    fn process_dump_scanner_detects_synthetic_marker() {
        let dump = temp_path("dump");
        let sentinels_path = temp_path("sentinels-dump");
        fs::write(&sentinels_path, "memory=DFSTL-MEMORY-SENTINEL-1234567890\n").expect("sentinels");
        fs::write(&dump, b"prefix DFSTL-MEMORY-SENTINEL-1234567890 suffix").expect("dump");
        let sentinels = load_sentinels(&sentinels_path).expect("load");
        let report = scan_process_dump(&dump, &sentinels).expect("scan");
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.scope, "process-dump");

        fs::remove_file(dump).expect("cleanup dump");
        fs::remove_file(sentinels_path).expect("cleanup sentinels");
    }

    #[test]
    fn synthetic_memory_buffer_is_cleared_in_place() {
        assert!(synthetic_memory_lifecycle_check());
    }
}
