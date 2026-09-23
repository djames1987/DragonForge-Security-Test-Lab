use std::fmt;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::hash::{hex_digest, sha256_bytes, sha256_file};

pub const MAX_SEED_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptedFormat {
    FileVault,
    Backup,
    SecureShare,
    Authenticator,
    PasswordManagerVault,
}

impl EncryptedFormat {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FileVault => "dfvault-file-vault",
            Self::Backup => "dfbackup",
            Self::SecureShare => "dfshare",
            Self::Authenticator => "dfauth",
            Self::PasswordManagerVault => "password-manager-dfvault",
        }
    }

    #[must_use]
    pub fn from_name(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "dfvault" | "file-vault" | "dfvault-file-vault" => Some(Self::FileVault),
            "dfbackup" | "backup" => Some(Self::Backup),
            "dfshare" | "share" | "secure-share" => Some(Self::SecureShare),
            "dfauth" | "authenticator" => Some(Self::Authenticator),
            "password-manager" | "password-manager-dfvault" | "pm-vault" => {
                Some(Self::PasswordManagerVault)
            }
            _ => None,
        }
    }

    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::FileVault | Self::PasswordManagerVault => "dfvault",
            Self::Backup => "dfbackup",
            Self::SecureShare => "dfshare",
            Self::Authenticator => "dfauth",
        }
    }
}

impl fmt::Display for EncryptedFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub enum MutationError {
    Io(io::Error),
    InputNotFound(PathBuf),
    InputNotRegular(PathBuf),
    SymlinkRejected(PathBuf),
    SeedTooLarge(u64),
    OutputExists(PathBuf),
    OutputInsideInput(PathBuf),
    SeedTooShort { required: usize, actual: usize },
    UnsupportedSeed(String),
}

impl fmt::Display for MutationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => f.write_str("encrypted-format mutation I/O failure"),
            Self::InputNotFound(path) => write!(f, "seed file not found: {}", path.display()),
            Self::InputNotRegular(path) => {
                write!(f, "seed path is not a regular file: {}", path.display())
            }
            Self::SymlinkRejected(path) => {
                write!(f, "seed symlink is not allowed: {}", path.display())
            }
            Self::SeedTooLarge(size) => {
                write!(f, "seed file exceeds {MAX_SEED_BYTES} bytes: {size}")
            }
            Self::OutputExists(path) => {
                write!(
                    f,
                    "mutation output directory already exists: {}",
                    path.display()
                )
            }
            Self::OutputInsideInput(path) => {
                write!(
                    f,
                    "mutation output cannot alias the seed path: {}",
                    path.display()
                )
            }
            Self::SeedTooShort { required, actual } => {
                write!(
                    f,
                    "seed is too short: requires {required} bytes, got {actual}"
                )
            }
            Self::UnsupportedSeed(reason) => {
                write!(f, "seed does not match format profile: {reason}")
            }
        }
    }
}

impl std::error::Error for MutationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for MutationError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationCase {
    pub id: String,
    pub description: String,
    pub file_name: String,
    pub sha256: String,
    pub size_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationCorpus {
    pub schema_version: u32,
    pub format: EncryptedFormat,
    pub seed_sha256: String,
    pub seed_size_bytes: usize,
    pub output_dir: PathBuf,
    pub cases: Vec<MutationCase>,
}

impl MutationCorpus {
    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(output, "{{");
        let _ = writeln!(output, "  \"schema_version\": {},", self.schema_version);
        let _ = writeln!(output, "  \"format\": \"{}\",", self.format.as_str());
        let _ = writeln!(output, "  \"seed_sha256\": \"{}\",", self.seed_sha256);
        let _ = writeln!(output, "  \"seed_size_bytes\": {},", self.seed_size_bytes);
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
                "      \"description\": \"{}\",",
                json_escape(&case.description)
            );
            let _ = writeln!(
                output,
                "      \"file_name\": \"{}\",",
                json_escape(&case.file_name)
            );
            let _ = writeln!(output, "      \"sha256\": \"{}\",", case.sha256);
            let _ = writeln!(output, "      \"size_bytes\": {}", case.size_bytes);
            let _ = writeln!(output, "    }}{comma}");
        }
        let _ = writeln!(output, "  ]");
        let _ = writeln!(output, "}}");
        output
    }

    #[must_use]
    pub fn to_text(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(output, "DragonForge encrypted-format mutation corpus");
        let _ = writeln!(output, "Format: {}", self.format);
        let _ = writeln!(output, "Seed SHA-256: {}", self.seed_sha256);
        let _ = writeln!(output, "Seed bytes: {}", self.seed_size_bytes);
        let _ = writeln!(output, "Cases: {}", self.cases.len());
        for case in &self.cases {
            let _ = writeln!(
                output,
                "{}  {} bytes  {}  {}",
                case.id, case.size_bytes, case.sha256, case.description
            );
        }
        output
    }
}

/// Generates a bounded mutation corpus from one explicit encrypted-format seed.
///
/// The seed is read-only. The output directory must not already exist.
///
/// # Errors
///
/// Returns an error for invalid seeds, unsafe paths, unsupported format shape,
/// or failed corpus writes.
pub fn generate_mutation_corpus(
    seed_path: &Path,
    format: EncryptedFormat,
    output_dir: &Path,
) -> Result<MutationCorpus, MutationError> {
    validate_seed_path(seed_path, output_dir)?;
    let metadata = fs::metadata(seed_path)?;
    if metadata.len() > MAX_SEED_BYTES {
        return Err(MutationError::SeedTooLarge(metadata.len()));
    }
    let seed = fs::read(seed_path)?;
    validate_seed(format, &seed)?;

    let seed_sha256 = hex_digest(&sha256_bytes(&seed));
    let raw_cases = match format {
        EncryptedFormat::FileVault | EncryptedFormat::Authenticator => binary_argon_cases(&seed),
        EncryptedFormat::Backup | EncryptedFormat::SecureShare => binary_length_cases(&seed),
        EncryptedFormat::PasswordManagerVault => password_manager_cases(&seed)?,
    };

    fs::create_dir(output_dir)?;
    let cases_dir = output_dir.join("cases");
    fs::create_dir(&cases_dir)?;

    let mut cases = Vec::with_capacity(raw_cases.len());
    for (id, description, bytes) in raw_cases {
        let file_name = format!("{id}.{}", format.extension());
        let destination = cases_dir.join(&file_name);
        write_new(&destination, &bytes)?;
        cases.push(MutationCase {
            id,
            description,
            file_name,
            sha256: hex_digest(&sha256_bytes(&bytes)),
            size_bytes: bytes.len(),
        });
    }

    let corpus = MutationCorpus {
        schema_version: 1,
        format,
        seed_sha256,
        seed_size_bytes: seed.len(),
        output_dir: output_dir.to_path_buf(),
        cases,
    };
    fs::write(output_dir.join("corpus.json"), corpus.to_json_pretty())?;
    fs::write(output_dir.join("corpus.txt"), corpus.to_text())?;
    write_hash_manifest(output_dir, &corpus)?;
    Ok(corpus)
}

fn validate_seed_path(seed_path: &Path, output_dir: &Path) -> Result<(), MutationError> {
    if !seed_path.exists() {
        return Err(MutationError::InputNotFound(seed_path.to_path_buf()));
    }
    let metadata = fs::symlink_metadata(seed_path)?;
    if metadata.file_type().is_symlink() {
        return Err(MutationError::SymlinkRejected(seed_path.to_path_buf()));
    }
    if !metadata.is_file() {
        return Err(MutationError::InputNotRegular(seed_path.to_path_buf()));
    }
    if output_dir.exists() {
        return Err(MutationError::OutputExists(output_dir.to_path_buf()));
    }

    let seed_absolute = absolute_lexical(seed_path)?;
    let output_absolute = absolute_lexical(output_dir)?;
    if seed_absolute == output_absolute || output_absolute.starts_with(&seed_absolute) {
        return Err(MutationError::OutputInsideInput(output_dir.to_path_buf()));
    }
    Ok(())
}

fn validate_seed(format: EncryptedFormat, seed: &[u8]) -> Result<(), MutationError> {
    match format {
        EncryptedFormat::FileVault => validate_binary_seed(seed, b"DFV1", 46),
        EncryptedFormat::Authenticator => validate_binary_seed(seed, b"DFA1", 46),
        EncryptedFormat::Backup => validate_binary_seed(seed, b"DFBACKUP", 46),
        EncryptedFormat::SecureShare => validate_binary_seed(seed, b"DFSHARE!", 46),
        EncryptedFormat::PasswordManagerVault => {
            let text = std::str::from_utf8(seed).map_err(|_| {
                MutationError::UnsupportedSeed("vault JSON is not UTF-8".to_owned())
            })?;
            if !text.trim_start().starts_with('{') || !text.contains("\"version\"") {
                return Err(MutationError::UnsupportedSeed(
                    "expected JSON object containing a version field".to_owned(),
                ));
            }
            Ok(())
        }
    }
}

fn validate_binary_seed(seed: &[u8], magic: &[u8], header_len: usize) -> Result<(), MutationError> {
    if seed.len() < header_len + 16 {
        return Err(MutationError::SeedTooShort {
            required: header_len + 16,
            actual: seed.len(),
        });
    }
    if !seed.starts_with(magic) {
        return Err(MutationError::UnsupportedSeed(format!(
            "expected magic {}",
            String::from_utf8_lossy(magic)
        )));
    }
    Ok(())
}

fn binary_argon_cases(seed: &[u8]) -> Vec<(String, String, Vec<u8>)> {
    let mut cases = common_binary_cases(seed, 46, 4);

    cases.push(mutate_u32(
        seed,
        "argon-memory-zero",
        "sets Argon2 memory cost to zero",
        6,
        0,
    ));
    cases.push(mutate_u32(
        seed,
        "argon-memory-max",
        "sets Argon2 memory cost to u32::MAX",
        6,
        u32::MAX,
    ));
    cases.push(mutate_u32(
        seed,
        "argon-iterations-zero",
        "sets Argon2 iterations to zero",
        10,
        0,
    ));
    cases.push(mutate_u32(
        seed,
        "argon-iterations-max",
        "sets Argon2 iterations to u32::MAX",
        10,
        u32::MAX,
    ));
    cases.push(mutate_u32(
        seed,
        "argon-lanes-zero",
        "sets Argon2 lanes to zero",
        14,
        0,
    ));
    cases.push(mutate_u32(
        seed,
        "argon-lanes-max",
        "sets Argon2 lanes to u32::MAX",
        14,
        u32::MAX,
    ));
    cases
}

fn binary_length_cases(seed: &[u8]) -> Vec<(String, String, Vec<u8>)> {
    let mut cases = common_binary_cases(seed, 46, 8);
    let actual_cipher_len = u64::try_from(seed.len().saturating_sub(46)).unwrap_or(u64::MAX);

    cases.push(mutate_u64(
        seed,
        "cipher-length-zero",
        "sets authenticated ciphertext length to zero",
        38,
        0,
    ));
    cases.push(mutate_u64(
        seed,
        "cipher-length-max",
        "sets authenticated ciphertext length to u64::MAX",
        38,
        u64::MAX,
    ));
    cases.push(mutate_u64(
        seed,
        "cipher-length-minus-one",
        "sets ciphertext length one byte below actual",
        38,
        actual_cipher_len.saturating_sub(1),
    ));
    cases.push(mutate_u64(
        seed,
        "cipher-length-plus-one",
        "sets ciphertext length one byte above actual",
        38,
        actual_cipher_len.saturating_add(1),
    ));
    cases
}

fn common_binary_cases(
    seed: &[u8],
    header_len: usize,
    version_offset: usize,
) -> Vec<(String, String, Vec<u8>)> {
    let mut cases = vec![
        (
            "empty".to_owned(),
            "zero-byte container".to_owned(),
            Vec::new(),
        ),
        (
            "truncate-one".to_owned(),
            "container truncated to one byte".to_owned(),
            seed[..1].to_vec(),
        ),
        (
            "truncate-header-minus-one".to_owned(),
            "container truncated one byte before full header".to_owned(),
            seed[..header_len - 1].to_vec(),
        ),
        (
            "truncate-header".to_owned(),
            "container truncated exactly at header boundary".to_owned(),
            seed[..header_len].to_vec(),
        ),
        (
            "truncate-half".to_owned(),
            "container truncated at midpoint".to_owned(),
            seed[..seed.len() / 2].to_vec(),
        ),
    ];

    let mut bad_magic = seed.to_vec();
    bad_magic[0] ^= 0xff;
    cases.push((
        "bad-magic".to_owned(),
        "flips the first magic byte".to_owned(),
        bad_magic,
    ));

    let mut future_version = seed.to_vec();
    future_version[version_offset..version_offset + 2].copy_from_slice(&u16::MAX.to_le_bytes());
    cases.push((
        "future-version".to_owned(),
        "sets format version to u16::MAX".to_owned(),
        future_version,
    ));

    let mut zero_version = seed.to_vec();
    zero_version[version_offset..version_offset + 2].copy_from_slice(&0_u16.to_le_bytes());
    cases.push((
        "zero-version".to_owned(),
        "sets format version to zero".to_owned(),
        zero_version,
    ));

    let mut header_tamper = seed.to_vec();
    header_tamper[header_len - 1] ^= 0x80;
    cases.push((
        "header-bitflip".to_owned(),
        "flips one authenticated header bit".to_owned(),
        header_tamper,
    ));

    let mut cipher_tamper = seed.to_vec();
    let cipher_index = header_len + (seed.len() - header_len) / 2;
    cipher_tamper[cipher_index] ^= 0x40;
    cases.push((
        "ciphertext-bitflip".to_owned(),
        "flips one ciphertext bit".to_owned(),
        cipher_tamper,
    ));

    let mut tag_tamper = seed.to_vec();
    let last = tag_tamper.len() - 1;
    tag_tamper[last] ^= 0x01;
    cases.push((
        "tag-bitflip".to_owned(),
        "flips the final authentication-tag byte".to_owned(),
        tag_tamper,
    ));

    let mut appended = seed.to_vec();
    appended.push(0);
    cases.push((
        "append-byte".to_owned(),
        "appends one trailing byte".to_owned(),
        appended,
    ));
    cases
}

fn password_manager_cases(seed: &[u8]) -> Result<Vec<(String, String, Vec<u8>)>, MutationError> {
    let text = std::str::from_utf8(seed)
        .map_err(|_| MutationError::UnsupportedSeed("vault JSON is not UTF-8".to_owned()))?;
    let mut cases = vec![
        ("empty".to_owned(), "zero-byte vault".to_owned(), Vec::new()),
        (
            "truncate-one".to_owned(),
            "vault truncated to one byte".to_owned(),
            seed[..1].to_vec(),
        ),
        (
            "truncate-half".to_owned(),
            "vault truncated at midpoint".to_owned(),
            seed[..seed.len() / 2].to_vec(),
        ),
        (
            "invalid-json".to_owned(),
            "replaces vault with malformed JSON".to_owned(),
            b"{\"version\":".to_vec(),
        ),
    ];

    if let Some(version_index) = find_version_value(text) {
        cases.push(json_number_mutation(
            seed,
            version_index,
            "zero-version",
            "sets vault version to zero",
            "0",
        ));
        cases.push(json_number_mutation(
            seed,
            version_index,
            "future-version",
            "sets vault version to 65535",
            "65535",
        ));
    } else {
        return Err(MutationError::UnsupportedSeed(
            "could not locate numeric version field".to_owned(),
        ));
    }

    let mut first_byte_tamper = seed.to_vec();
    if let Some(index) = first_byte_tamper.iter().position(u8::is_ascii_alphanumeric) {
        first_byte_tamper[index] ^= 0x01;
    }
    cases.push((
        "json-bitflip".to_owned(),
        "flips one JSON content byte".to_owned(),
        first_byte_tamper,
    ));

    let mut appended = seed.to_vec();
    appended.extend_from_slice(b"\n{}");
    cases.push((
        "append-json-object".to_owned(),
        "appends a second JSON object".to_owned(),
        appended,
    ));

    Ok(cases)
}

fn find_version_value(text: &str) -> Option<usize> {
    let key = "\"version\"";
    let key_start = text.find(key)?;
    let after_key = &text[key_start + key.len()..];
    let colon = after_key.find(':')?;
    let value_start = key_start + key.len() + colon + 1;
    let suffix = &text[value_start..];
    let whitespace = suffix.len() - suffix.trim_start().len();
    let numeric_start = value_start + whitespace;
    text.as_bytes()
        .get(numeric_start)
        .filter(|byte| byte.is_ascii_digit())
        .map(|_| numeric_start)
}

fn json_number_mutation(
    seed: &[u8],
    start: usize,
    id: &str,
    description: &str,
    replacement: &str,
) -> (String, String, Vec<u8>) {
    let mut end = start;
    while end < seed.len() && seed[end].is_ascii_digit() {
        end += 1;
    }
    let mut bytes = Vec::with_capacity(seed.len() + replacement.len());
    bytes.extend_from_slice(&seed[..start]);
    bytes.extend_from_slice(replacement.as_bytes());
    bytes.extend_from_slice(&seed[end..]);
    (id.to_owned(), description.to_owned(), bytes)
}

fn mutate_u32(
    seed: &[u8],
    id: &str,
    description: &str,
    offset: usize,
    value: u32,
) -> (String, String, Vec<u8>) {
    let mut bytes = seed.to_vec();
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    (id.to_owned(), description.to_owned(), bytes)
}

fn mutate_u64(
    seed: &[u8],
    id: &str,
    description: &str,
    offset: usize,
    value: u64,
) -> (String, String, Vec<u8>) {
    let mut bytes = seed.to_vec();
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    (id.to_owned(), description.to_owned(), bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), MutationError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_hash_manifest(output_dir: &Path, corpus: &MutationCorpus) -> Result<(), MutationError> {
    let mut manifest = String::new();
    for case in &corpus.cases {
        let _ = writeln!(manifest, "{}  cases/{}", case.sha256, case.file_name);
    }
    for name in ["corpus.json", "corpus.txt"] {
        let digest = hex_digest(&sha256_file(&output_dir.join(name))?);
        let _ = writeln!(manifest, "{digest}  {name}");
    }
    fs::write(output_dir.join("SHA256SUMS"), manifest)?;
    Ok(())
}

fn absolute_lexical(path: &Path) -> Result<PathBuf, MutationError> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
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

    use super::{EncryptedFormat, generate_mutation_corpus};

    fn temp_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "dfstl-mutation-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn argon_seed(magic: [u8; 4]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&magic);
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.extend_from_slice(&65_536_u32.to_le_bytes());
        bytes.extend_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&[7_u8; 16]);
        bytes.extend_from_slice(&[9_u8; 12]);
        bytes.extend_from_slice(&[0x55_u8; 32]);
        bytes
    }

    fn length_seed(magic: [u8; 8]) -> Vec<u8> {
        let ciphertext = [0x66_u8; 32];
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&magic);
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.extend_from_slice(&[7_u8; 16]);
        bytes.extend_from_slice(&[9_u8; 12]);
        let ciphertext_len = u64::try_from(ciphertext.len()).expect("synthetic length fits u64");
        bytes.extend_from_slice(&ciphertext_len.to_le_bytes());
        bytes.extend_from_slice(&ciphertext);
        bytes
    }

    fn write_seed(label: &str, bytes: &[u8]) -> PathBuf {
        let path = temp_path(label);
        fs::write(&path, bytes).expect("seed");
        path
    }

    #[test]
    fn file_vault_corpus_contains_argon_and_tamper_cases() {
        let seed = write_seed("dfvault", &argon_seed(*b"DFV1"));
        let output = temp_path("dfvault-out");
        let corpus =
            generate_mutation_corpus(&seed, EncryptedFormat::FileVault, &output).expect("corpus");

        assert!(corpus.cases.len() >= 18);
        assert!(
            corpus
                .cases
                .iter()
                .any(|case| case.id == "argon-memory-max")
        );
        assert!(
            corpus
                .cases
                .iter()
                .any(|case| case.id == "ciphertext-bitflip")
        );
        assert!(output.join("SHA256SUMS").is_file());

        fs::remove_file(seed).expect("cleanup seed");
        fs::remove_dir_all(output).expect("cleanup output");
    }

    #[test]
    fn authenticator_profile_rejects_wrong_magic() {
        let seed = write_seed("wrong-auth", &argon_seed(*b"DFV1"));
        let output = temp_path("wrong-auth-out");
        assert!(generate_mutation_corpus(&seed, EncryptedFormat::Authenticator, &output).is_err());
        fs::remove_file(seed).expect("cleanup");
    }

    #[test]
    fn backup_corpus_contains_length_boundary_cases() {
        let seed = write_seed("backup", &length_seed(*b"DFBACKUP"));
        let output = temp_path("backup-out");
        let corpus =
            generate_mutation_corpus(&seed, EncryptedFormat::Backup, &output).expect("corpus");

        assert!(
            corpus
                .cases
                .iter()
                .any(|case| case.id == "cipher-length-max")
        );
        assert!(
            corpus
                .cases
                .iter()
                .any(|case| case.id == "cipher-length-minus-one")
        );

        fs::remove_file(seed).expect("cleanup seed");
        fs::remove_dir_all(output).expect("cleanup output");
    }

    #[test]
    fn secure_share_profile_accepts_current_magic() {
        let seed = write_seed("share", &length_seed(*b"DFSHARE!"));
        let output = temp_path("share-out");
        let corpus =
            generate_mutation_corpus(&seed, EncryptedFormat::SecureShare, &output).expect("corpus");
        assert!(corpus.cases.len() >= 16);

        fs::remove_file(seed).expect("cleanup seed");
        fs::remove_dir_all(output).expect("cleanup output");
    }

    #[test]
    fn password_manager_profile_mutates_json_version() {
        let seed = write_seed("pm", br#"{"version":1,"vault_id":"synthetic","items":[]}"#);
        let output = temp_path("pm-out");
        let corpus =
            generate_mutation_corpus(&seed, EncryptedFormat::PasswordManagerVault, &output)
                .expect("corpus");

        assert!(corpus.cases.iter().any(|case| case.id == "zero-version"));
        assert!(corpus.cases.iter().any(|case| case.id == "future-version"));

        fs::remove_file(seed).expect("cleanup seed");
        fs::remove_dir_all(output).expect("cleanup output");
    }

    #[test]
    fn existing_output_is_never_overwritten() {
        let seed = write_seed("existing", &argon_seed(*b"DFA1"));
        let output = temp_path("existing-out");
        fs::create_dir(&output).expect("output");
        fs::write(output.join("sentinel.txt"), b"keep").expect("sentinel");

        assert!(
            generate_mutation_corpus(&seed, EncryptedFormat::Authenticator, &output).is_err()
        );
        assert_eq!(
            fs::read(output.join("sentinel.txt")).expect("sentinel"),
            b"keep"
        );

        fs::remove_file(seed).expect("cleanup seed");
        fs::remove_dir_all(output).expect("cleanup output");
    }
}
