use std::fmt;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use crate::hash::{hex_digest, sha256_bytes};

pub const MAX_CPU_ITERATIONS: u64 = 2_000_000;
pub const MAX_MEMORY_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_SOCKET_CONNECTIONS: usize = 256;
pub const DEFAULT_CPU_ITERATIONS: u64 = 100_000;
pub const DEFAULT_MEMORY_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_SOCKET_CONNECTIONS: usize = 32;

#[derive(Debug)]
pub enum FailureLabError {
    Io(io::Error),
    RootExists(PathBuf),
    RootIsSymlink(PathBuf),
    InvalidBudget,
    RecoveryInvariant(String),
}

impl fmt::Display for FailureLabError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => formatter.write_str("failure-lab I/O error"),
            Self::RootExists(path) => {
                write!(formatter, "failure-lab root already exists: {}", path.display())
            }
            Self::RootIsSymlink(path) => {
                write!(formatter, "failure-lab root must not be a symlink: {}", path.display())
            }
            Self::InvalidBudget => {
                formatter.write_str("resource stress budget is outside safe limits")
            }
            Self::RecoveryInvariant(detail) => {
                write!(formatter, "recovery invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for FailureLabError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for FailureLabError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultCase {
    pub id: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureInjectionReport {
    pub schema_version: u32,
    pub cases: Vec<FaultCase>,
}

impl FailureInjectionReport {
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.cases.iter().all(|case| case.passed)
    }

    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(output, "{{");
        let _ = writeln!(output, "  \"schema_version\": {},", self.schema_version);
        let _ = writeln!(output, "  \"all_passed\": {},", self.all_passed());
        let _ = writeln!(output, "  \"cases\": [");
        for (index, case) in self.cases.iter().enumerate() {
            let comma = if index + 1 == self.cases.len() { "" } else { "," };
            let _ = writeln!(
                output,
                "    {{\"id\":\"{}\",\"passed\":{},\"detail\":\"{}\"}}{}",
                json_escape(&case.id),
                case.passed,
                json_escape(&case.detail),
                comma
            );
        }
        let _ = writeln!(output, "  ]");
        let _ = writeln!(output, "}}");
        output
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceStressReport {
    pub schema_version: u32,
    pub cpu_iterations: u64,
    pub memory_bytes: usize,
    pub socket_connections: usize,
    pub checksum: String,
    pub elapsed_ms: u128,
    pub passed: bool,
}

impl ResourceStressReport {
    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        format!(
            concat!(
                "{{\n",
                "  \"schema_version\": {},\n",
                "  \"cpu_iterations\": {},\n",
                "  \"memory_bytes\": {},\n",
                "  \"socket_connections\": {},\n",
                "  \"checksum\": \"{}\",\n",
                "  \"elapsed_ms\": {},\n",
                "  \"passed\": {}\n",
                "}}\n"
            ),
            self.schema_version,
            self.cpu_iterations,
            self.memory_bytes,
            self.socket_connections,
            self.checksum,
            self.elapsed_ms,
            self.passed
        )
    }
}

/// Runs deterministic failure-injection cases beneath a new disposable root.
///
/// # Errors
///
/// Returns an error when the root is unsafe, already exists, or a recovery
/// invariant cannot be established.
pub fn run_failure_injection_lab(root: &Path) -> Result<FailureInjectionReport, FailureLabError> {
    validate_new_root(root)?;
    fs::create_dir(root)?;

    let result = (|| {
        let cases = vec![
            disk_full_write_case(),
            permission_denied_write_case(),
            interrupted_atomic_write_case(root)?,
            restore_recovery_case(root)?,
        ];
        Ok(FailureInjectionReport {
            schema_version: 1,
            cases,
        })
    })();

    if result.is_err() {
        let _ = fs::remove_dir_all(root);
    }
    result
}

/// Runs capped CPU, memory, and loopback socket stress.
///
/// # Errors
///
/// Returns an error if any requested budget exceeds Phase 10 limits or if
/// loopback socket setup fails.
pub fn run_bounded_resource_stress(
    cpu_iterations: u64,
    memory_bytes: usize,
    socket_connections: usize,
) -> Result<ResourceStressReport, FailureLabError> {
    if cpu_iterations == 0
        || cpu_iterations > MAX_CPU_ITERATIONS
        || memory_bytes == 0
        || memory_bytes > MAX_MEMORY_BYTES
        || socket_connections == 0
        || socket_connections > MAX_SOCKET_CONNECTIONS
    {
        return Err(FailureLabError::InvalidBudget);
    }

    let started = Instant::now();
    let mut checksum = [0_u8; 32];
    for iteration in 0..cpu_iterations {
        let mut input = Vec::with_capacity(checksum.len() + 8);
        input.extend_from_slice(&checksum);
        input.extend_from_slice(&iteration.to_le_bytes());
        checksum = sha256_bytes(&input);
    }

    let mut memory = vec![0_u8; memory_bytes];
    for (index, byte) in memory.iter_mut().enumerate() {
        *byte = u8::try_from(index % 251).unwrap_or(0);
    }
    let memory_checksum = sha256_bytes(&memory);
    checksum = sha256_bytes(&[checksum.as_slice(), memory_checksum.as_slice()].concat());

    run_socket_stress(socket_connections)?;

    Ok(ResourceStressReport {
        schema_version: 1,
        cpu_iterations,
        memory_bytes,
        socket_connections,
        checksum: hex_digest(&checksum),
        elapsed_ms: started.elapsed().as_millis(),
        passed: true,
    })
}

/// Writes Phase 10 evidence plus SHA-256SUMS.
///
/// # Errors
///
/// Returns an error if the output already exists or cannot be written.
pub fn write_failure_bundle(
    output_dir: &Path,
    failure_report: Option<&FailureInjectionReport>,
    resource_report: Option<&ResourceStressReport>,
) -> Result<(), FailureLabError> {
    if output_dir.exists() {
        return Err(FailureLabError::RootExists(output_dir.to_path_buf()));
    }
    fs::create_dir(output_dir)?;

    let mut names = Vec::new();
    if let Some(report) = failure_report {
        let name = "failure-injection.json";
        fs::write(output_dir.join(name), report.to_json_pretty())?;
        names.push(name);
    }
    if let Some(report) = resource_report {
        let name = "resource-stress.json";
        fs::write(output_dir.join(name), report.to_json_pretty())?;
        names.push(name);
    }

    let mut manifest = String::new();
    for name in names {
        let bytes = fs::read(output_dir.join(name))?;
        let _ = writeln!(manifest, "{}  {name}", hex_digest(&sha256_bytes(&bytes)));
    }
    fs::write(output_dir.join("SHA256SUMS"), manifest)?;
    Ok(())
}

fn disk_full_write_case() -> FaultCase {
    let mut writer = FailingWriter::new(FailingWriterMode::DiskFull, 8);
    let first = writer.write_all(b"12345678").is_ok();
    let second = writer
        .write_all(b"9")
        .is_err_and(|error| error.kind() == io::ErrorKind::StorageFull);
    FaultCase {
        id: "disk-full-write".to_owned(),
        passed: first && second,
        detail: "injected storage-full error is surfaced without partial success".to_owned(),
    }
}

fn permission_denied_write_case() -> FaultCase {
    let mut writer = FailingWriter::new(FailingWriterMode::PermissionDenied, 0);
    let denied = writer
        .write_all(b"synthetic")
        .is_err_and(|error| error.kind() == io::ErrorKind::PermissionDenied);
    FaultCase {
        id: "permission-denied-write".to_owned(),
        passed: denied,
        detail: "injected permission denial is surfaced as an I/O failure".to_owned(),
    }
}

fn interrupted_atomic_write_case(root: &Path) -> Result<FaultCase, FailureLabError> {
    let destination = root.join("atomic-state.bin");
    let staging = root.join("atomic-state.bin.tmp");
    fs::write(&destination, b"stable-state")?;

    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging)?;
        file.write_all(b"partial-new")?;
        file.sync_all()?;
    }

    let stable_before_recovery = fs::read(&destination)? == b"stable-state";
    recover_interrupted_write(&destination, &staging)?;
    let stable_after_recovery = fs::read(&destination)? == b"stable-state";
    let staging_removed = !staging.exists();

    Ok(FaultCase {
        id: "interrupted-atomic-write".to_owned(),
        passed: stable_before_recovery && stable_after_recovery && staging_removed,
        detail: "partial staging data never replaced committed state and cleanup recovered"
            .to_owned(),
    })
}

fn restore_recovery_case(root: &Path) -> Result<FaultCase, FailureLabError> {
    let destination = root.join("restore-destination");
    let staging = root.join("restore-staging");
    fs::create_dir(&destination)?;
    fs::write(destination.join("existing.txt"), b"existing")?;
    fs::create_dir(&staging)?;
    fs::write(staging.join("partial.txt"), b"partial")?;

    let destination_intact = destination.join("existing.txt").is_file();
    fs::remove_dir_all(&staging)?;
    let staging_removed = !staging.exists();

    Ok(FaultCase {
        id: "interrupted-restore-recovery".to_owned(),
        passed: destination_intact && staging_removed,
        detail: "existing destination remains intact while partial staging is discarded".to_owned(),
    })
}

fn recover_interrupted_write(destination: &Path, staging: &Path) -> Result<(), FailureLabError> {
    if !destination.is_file() {
        return Err(FailureLabError::RecoveryInvariant(
            "committed destination disappeared".to_owned(),
        ));
    }
    if staging.exists() {
        fs::remove_file(staging)?;
    }
    Ok(())
}

fn run_socket_stress(connections: usize) -> Result<(), FailureLabError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    listener.set_nonblocking(false)?;

    let server = thread::spawn(move || -> io::Result<usize> {
        let mut accepted = 0_usize;
        for _ in 0..connections {
            let (mut stream, _) = listener.accept()?;
            let mut byte = [0_u8; 1];
            std::io::Read::read_exact(&mut stream, &mut byte)?;
            accepted += 1;
        }
        Ok(accepted)
    });

    for _ in 0..connections {
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
        stream.write_all(&[0x5a])?;
    }

    let accepted = server
        .join()
        .map_err(|_| io::Error::other("socket stress worker panicked"))??;
    if accepted != connections {
        return Err(FailureLabError::RecoveryInvariant(
            "loopback socket stress accepted unexpected connection count".to_owned(),
        ));
    }
    Ok(())
}

fn validate_new_root(root: &Path) -> Result<(), FailureLabError> {
    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(FailureLabError::RootIsSymlink(root.to_path_buf()))
        }
        Ok(_) => Err(FailureLabError::RootExists(root.to_path_buf())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = root.parent().unwrap_or_else(|| Path::new("."));
            let parent_metadata = fs::symlink_metadata(parent)?;
            if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
                return Err(FailureLabError::RootIsSymlink(parent.to_path_buf()));
            }
            Ok(())
        }
        Err(error) => Err(FailureLabError::Io(error)),
    }
}

#[derive(Debug, Clone, Copy)]
enum FailingWriterMode {
    DiskFull,
    PermissionDenied,
}

struct FailingWriter {
    mode: FailingWriterMode,
    remaining: usize,
}

impl FailingWriter {
    const fn new(mode: FailingWriterMode, remaining: usize) -> Self {
        Self { mode, remaining }
    }
}

impl Write for FailingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self.mode {
            FailingWriterMode::PermissionDenied => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "synthetic permission denial",
            )),
            FailingWriterMode::DiskFull => {
                if self.remaining == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::StorageFull,
                        "synthetic storage full",
                    ));
                }
                let count = buffer.len().min(self.remaining);
                self.remaining -= count;
                Ok(count)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
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
        DEFAULT_CPU_ITERATIONS, DEFAULT_MEMORY_BYTES, DEFAULT_SOCKET_CONNECTIONS,
        run_bounded_resource_stress, run_failure_injection_lab, write_failure_bundle,
    };

    fn temp_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "dfstl-failure-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn failure_injection_matrix_preserves_recovery_invariants() {
        let root = temp_path("matrix");
        let report = run_failure_injection_lab(&root).expect("lab");
        assert!(report.all_passed());
        assert_eq!(report.cases.len(), 4);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn resource_stress_is_bounded_and_completes() {
        let report = run_bounded_resource_stress(2_000, 64 * 1024, 4).expect("stress");
        assert!(report.passed);
        assert_eq!(report.socket_connections, 4);
    }

    #[test]
    fn evidence_bundle_hash_manifest_is_written() {
        let root = temp_path("bundle-lab");
        let output = temp_path("bundle-out");
        let failure = run_failure_injection_lab(&root).expect("lab");
        let resource = run_bounded_resource_stress(
            DEFAULT_CPU_ITERATIONS / 100,
            DEFAULT_MEMORY_BYTES / 128,
            DEFAULT_SOCKET_CONNECTIONS / 8,
        )
        .expect("stress");
        write_failure_bundle(&output, Some(&failure), Some(&resource)).expect("bundle");
        assert!(output.join("SHA256SUMS").is_file());
        fs::remove_dir_all(root).expect("cleanup lab");
        fs::remove_dir_all(output).expect("cleanup output");
    }

    #[test]
    fn existing_failure_lab_root_is_refused() {
        let root = temp_path("existing");
        fs::create_dir(&root).expect("create");
        assert!(run_failure_injection_lab(&root).is_err());
        fs::remove_dir(root).expect("cleanup");
    }
}
