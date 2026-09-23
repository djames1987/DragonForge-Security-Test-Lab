use std::fmt;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::hash::{hex_digest, sha256_file};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceLimits {
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_files: usize,
}

impl Default for EvidenceLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: 1024 * 1024,
            max_total_bytes: 8 * 1024 * 1024,
            max_files: 128,
        }
    }
}

#[derive(Debug)]
pub enum EvidenceError {
    Io(io::Error),
    InvalidRunId,
    InvalidArtifactPath,
    ArtifactTooLarge,
    ArtifactAlreadyExists,
    EvidenceLimitExceeded,
    TooManyFiles,
    SymlinkRejected,
    FinalDestinationExists,
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Io(_) => "evidence I/O failure",
            Self::InvalidRunId => "invalid run identifier",
            Self::InvalidArtifactPath => "invalid artifact path",
            Self::ArtifactTooLarge => "artifact exceeds per-file evidence limit",
            Self::ArtifactAlreadyExists => "artifact path already exists",
            Self::EvidenceLimitExceeded => "evidence exceeds total byte limit",
            Self::TooManyFiles => "evidence exceeds file-count limit",
            Self::SymlinkRejected => "symlink encountered in evidence tree",
            Self::FinalDestinationExists => "final evidence destination already exists",
        };
        f.write_str(message)
    }
}

impl std::error::Error for EvidenceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for EvidenceError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub struct EvidenceSession {
    root: PathBuf,
    staging: PathBuf,
    final_dir: PathBuf,
    limits: EvidenceLimits,
    bytes_written: u64,
    files_written: usize,
    finalized: bool,
}

impl EvidenceSession {
    /// Creates an isolated staging directory for one run.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid run identifier or if the staging
    /// directory cannot be safely created.
    pub fn new(
        root: impl AsRef<Path>,
        run_id: &str,
        limits: EvidenceLimits,
    ) -> Result<Self, EvidenceError> {
        if !valid_run_id(run_id) {
            return Err(EvidenceError::InvalidRunId);
        }

        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        let staging = root.join(format!(".{run_id}.staging"));
        let final_dir = root.join(run_id);

        if final_dir.exists() {
            return Err(EvidenceError::FinalDestinationExists);
        }
        if staging.exists() {
            fs::remove_dir_all(&staging)?;
        }
        fs::create_dir(&staging)?;

        Ok(Self {
            root,
            staging,
            final_dir,
            limits,
            bytes_written: 0,
            files_written: 0,
            finalized: false,
        })
    }

    /// Writes an artifact beneath the run staging directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is unsafe, evidence bounds are exceeded,
    /// or the file cannot be written.
    pub fn write_artifact(
        &mut self,
        relative_path: impl AsRef<Path>,
        bytes: &[u8],
    ) -> Result<(), EvidenceError> {
        let relative_path = relative_path.as_ref();
        validate_relative_path(relative_path)?;

        let byte_count =
            u64::try_from(bytes.len()).map_err(|_| EvidenceError::ArtifactTooLarge)?;
        if byte_count > self.limits.max_file_bytes {
            return Err(EvidenceError::ArtifactTooLarge);
        }
        let new_total = self
            .bytes_written
            .checked_add(byte_count)
            .ok_or(EvidenceError::EvidenceLimitExceeded)?;
        if new_total > self.limits.max_total_bytes {
            return Err(EvidenceError::EvidenceLimitExceeded);
        }
        if self.files_written >= self.limits.max_files {
            return Err(EvidenceError::TooManyFiles);
        }

        let destination = self.staging.join(relative_path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }

        let temporary = destination.with_extension("dfstl-tmp");
        if destination.exists() || temporary.exists() {
            return Err(EvidenceError::ArtifactAlreadyExists);
        }
        fs::write(&temporary, bytes)?;
        fs::rename(&temporary, &destination)?;

        self.bytes_written = new_total;
        self.files_written += 1;
        Ok(())
    }

    /// Finalizes the run, writes reports and a SHA-256 manifest, then
    /// atomically promotes the staging directory to its final run directory.
    ///
    /// # Errors
    ///
    /// Returns an error if report persistence, hashing, manifest generation,
    /// or final promotion fails.
    pub fn finalize(
        mut self,
        report_json: &str,
        report_text: &str,
    ) -> Result<PathBuf, EvidenceError> {
        self.write_artifact("report.json", report_json.as_bytes())?;
        self.write_artifact("report.txt", report_text.as_bytes())?;

        let mut files = Vec::new();
        collect_regular_files(&self.staging, &self.staging, &mut files)?;
        files.sort();

        let mut manifest = String::new();
        for relative in &files {
            let digest = sha256_file(&self.staging.join(relative))?;
            manifest.push_str(&hex_digest(&digest));
            manifest.push_str("  ");
            manifest.push_str(&relative.to_string_lossy().replace('\\', "/"));
            manifest.push('\n');
        }
        self.write_artifact("SHA256SUMS", manifest.as_bytes())?;

        if self.final_dir.exists() {
            return Err(EvidenceError::FinalDestinationExists);
        }
        fs::rename(&self.staging, &self.final_dir)?;
        self.finalized = true;
        Ok(self.final_dir.clone())
    }

    #[must_use]
    pub fn staging_dir(&self) -> &Path {
        &self.staging
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl Drop for EvidenceSession {
    fn drop(&mut self) {
        if !self.finalized && self.staging.exists() {
            let _ = fs::remove_dir_all(&self.staging);
        }
    }
}

fn valid_run_id(run_id: &str) -> bool {
    !run_id.is_empty()
        && run_id.len() <= 96
        && run_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn validate_relative_path(path: &Path) -> Result<(), EvidenceError> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(EvidenceError::InvalidArtifactPath);
    }
    for component in path.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(EvidenceError::InvalidArtifactPath);
        }
    }
    Ok(())
}

fn collect_regular_files(
    base: &Path,
    current: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), EvidenceError> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            return Err(EvidenceError::SymlinkRejected);
        }
        if metadata.is_dir() {
            collect_regular_files(base, &entry.path(), files)?;
        } else if metadata.is_file() {
            let relative = entry
                .path()
                .strip_prefix(base)
                .map_err(|_| EvidenceError::InvalidArtifactPath)?
                .to_path_buf();
            files.push(relative);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{EvidenceError, EvidenceLimits, EvidenceSession};

    fn temp_root(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("dfstl-{label}-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn evidence_session_finalizes_reports_artifacts_and_manifest() {
        let root = temp_root("evidence");
        let mut session =
            EvidenceSession::new(&root, "run-test", EvidenceLimits::default()).expect("session");
        session
            .write_artifact("artifacts/example.txt", b"synthetic evidence")
            .expect("artifact");
        let final_dir = session
            .finalize("{\"schema\":1}", "DFSTL test report")
            .expect("finalize");

        assert!(final_dir.join("artifacts/example.txt").is_file());
        assert!(final_dir.join("report.json").is_file());
        assert!(final_dir.join("report.txt").is_file());
        let manifest = fs::read_to_string(final_dir.join("SHA256SUMS")).expect("manifest");
        assert!(manifest.contains("artifacts/example.txt"));
        assert!(manifest.contains("report.json"));
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn traversal_and_absolute_paths_are_rejected() {
        let root = temp_root("paths");
        let mut session =
            EvidenceSession::new(&root, "run-test", EvidenceLimits::default()).expect("session");
        assert!(matches!(
            session.write_artifact("../escape.txt", b"x"),
            Err(EvidenceError::InvalidArtifactPath)
        ));
        assert!(matches!(
            session.write_artifact(root.join("absolute.txt"), b"x"),
            Err(EvidenceError::InvalidArtifactPath)
        ));
        drop(session);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn duplicate_artifact_paths_are_rejected() {
        let root = temp_root("duplicate");
        let mut session =
            EvidenceSession::new(&root, "run-test", EvidenceLimits::default()).expect("session");
        session.write_artifact("proof.txt", b"first").expect("first");
        assert!(matches!(
            session.write_artifact("proof.txt", b"second"),
            Err(EvidenceError::ArtifactAlreadyExists)
        ));
        drop(session);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn evidence_limits_are_enforced() {
        let root = temp_root("limits");
        let limits = EvidenceLimits {
            max_file_bytes: 4,
            max_total_bytes: 6,
            max_files: 2,
        };
        let mut session = EvidenceSession::new(&root, "run-test", limits).expect("session");
        assert!(matches!(
            session.write_artifact("too-large.bin", b"12345"),
            Err(EvidenceError::ArtifactTooLarge)
        ));
        session.write_artifact("one.bin", b"1234").expect("first");
        assert!(matches!(
            session.write_artifact("two.bin", b"123"),
            Err(EvidenceError::EvidenceLimitExceeded)
        ));
        drop(session);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn abandoned_staging_directory_is_cleaned_on_drop() {
        let root = temp_root("drop");
        let staging = {
            let session = EvidenceSession::new(
                &root,
                "run-test",
                EvidenceLimits::default(),
            )
            .expect("session");
            session.staging_dir().to_path_buf()
        };
        assert!(!staging.exists());
        fs::remove_dir_all(root).expect("cleanup");
    }
}
