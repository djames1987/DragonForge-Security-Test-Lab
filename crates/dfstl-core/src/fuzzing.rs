use std::fmt;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::hash::{hex_digest, sha256_bytes};

pub const MAX_FUZZ_SEED_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_FUZZ_CASES: usize = 256;
pub const DEFAULT_FUZZ_CASES: usize = 32;

#[derive(Debug)]
pub enum FuzzError {
    Io(io::Error),
    SeedTooLarge(usize),
    InvalidCaseCount(usize),
    OutputExists(PathBuf),
    RegressionExists(PathBuf),
    InvalidTarget(String),
}

impl fmt::Display for FuzzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => f.write_str("fuzz corpus I/O failure"),
            Self::SeedTooLarge(size) => write!(f, "fuzz seed exceeds safe size limit: {size}"),
            Self::InvalidCaseCount(count) => write!(f, "invalid fuzz case count: {count}"),
            Self::OutputExists(path) => write!(f, "fuzz output already exists: {}", path.display()),
            Self::RegressionExists(path) => {
                write!(f, "regression fixture already exists: {}", path.display())
            }
            Self::InvalidTarget(target) => write!(f, "unknown fuzz target: {target}"),
        }
    }
}

impl std::error::Error for FuzzError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for FuzzError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzTarget {
    DfVault,
    DfBackup,
    DfShare,
    DfAuth,
    PasswordManagerJson,
    AgentJson,
    SyncHttp,
    WindowsPath,
}

impl FuzzTarget {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DfVault => "dfvault",
            Self::DfBackup => "dfbackup",
            Self::DfShare => "dfshare",
            Self::DfAuth => "dfauth",
            Self::PasswordManagerJson => "password-manager-json",
            Self::AgentJson => "agent-json",
            Self::SyncHttp => "sync-http",
            Self::WindowsPath => "windows-path",
        }
    }

    /// Parses a stable fuzz target name.
    ///
    /// # Errors
    ///
    /// Returns InvalidTarget for unknown names.
    pub fn parse(value: &str) -> Result<Self, FuzzError> {
        match value {
            "dfvault" => Ok(Self::DfVault),
            "dfbackup" => Ok(Self::DfBackup),
            "dfshare" => Ok(Self::DfShare),
            "dfauth" => Ok(Self::DfAuth),
            "password-manager-json" => Ok(Self::PasswordManagerJson),
            "agent-json" => Ok(Self::AgentJson),
            "sync-http" => Ok(Self::SyncHttp),
            "windows-path" => Ok(Self::WindowsPath),
            other => Err(FuzzError::InvalidTarget(other.to_owned())),
        }
    }

    #[must_use]
    pub const fn all() -> [Self; 8] {
        [
            Self::DfVault,
            Self::DfBackup,
            Self::DfShare,
            Self::DfAuth,
            Self::PasswordManagerJson,
            Self::AgentJson,
            Self::SyncHttp,
            Self::WindowsPath,
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzCase {
    pub id: String,
    pub filename: String,
    pub sha256: String,
    pub size: usize,
    pub mutation: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzCorpus {
    pub schema_version: u32,
    pub target: String,
    pub rng_seed: u64,
    pub source_sha256: String,
    pub cases: Vec<FuzzCase>,
}

impl FuzzCorpus {
    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(output, "{{");
        let _ = writeln!(output, "  \"schema_version\": {},", self.schema_version);
        let _ = writeln!(output, "  \"target\": \"{}\",", json_escape(&self.target));
        let _ = writeln!(output, "  \"rng_seed\": {},", self.rng_seed);
        let _ = writeln!(output, "  \"source_sha256\": \"{}\",", self.source_sha256);
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
                    "    {\"id\":\"{}\",\"filename\":\"{}\",",
                    "\"sha256\":\"{}\",\"size\":{},\"mutation\":\"{}\"}{}"
                ),
                json_escape(&case.id),
                json_escape(&case.filename),
                case.sha256,
                case.size,
                json_escape(&case.mutation),
                comma
            );
        }
        let _ = writeln!(output, "  ]");
        let _ = writeln!(output, "}}");
        output
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegressionFixture {
    pub schema_version: u32,
    pub target: String,
    pub filename: String,
    pub sha256: String,
    pub source_name: String,
    pub note: String,
}

impl RegressionFixture {
    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        format!(
            concat!(
                "{{\n",
                "  \"schema_version\": {},\n",
                "  \"target\": \"{}\",\n",
                "  \"filename\": \"{}\",\n",
                "  \"sha256\": \"{}\",\n",
                "  \"source_name\": \"{}\",\n",
                "  \"note\": \"{}\"\n",
                "}}\n"
            ),
            self.schema_version,
            json_escape(&self.target),
            json_escape(&self.filename),
            self.sha256,
            json_escape(&self.source_name),
            json_escape(&self.note)
        )
    }
}

/// Generates a deterministic, bounded structure-aware mutation corpus.
///
/// # Errors
///
/// Returns an error for oversized seeds, invalid case counts, or existing output.
pub fn generate_fuzz_corpus(
    target: FuzzTarget,
    seed_path: &Path,
    output_dir: &Path,
    rng_seed: u64,
    case_count: usize,
) -> Result<FuzzCorpus, FuzzError> {
    if output_dir.exists() {
        return Err(FuzzError::OutputExists(output_dir.to_path_buf()));
    }
    if case_count == 0 || case_count > MAX_FUZZ_CASES {
        return Err(FuzzError::InvalidCaseCount(case_count));
    }

    let seed = fs::read(seed_path)?;
    if seed.len() > MAX_FUZZ_SEED_BYTES {
        return Err(FuzzError::SeedTooLarge(seed.len()));
    }

    fs::create_dir(output_dir)?;
    let mut rng = XorShift64::new(rng_seed);
    let mut cases = Vec::with_capacity(case_count);

    for index in 0..case_count {
        let (bytes, mutation) = mutate_case(target, &seed, index, &mut rng);
        let filename = format!("case-{index:04}.bin");
        fs::write(output_dir.join(&filename), &bytes)?;
        cases.push(FuzzCase {
            id: format!("{}-{index:04}", target.as_str()),
            filename,
            sha256: hex_digest(&sha256_bytes(&bytes)),
            size: bytes.len(),
            mutation,
        });
    }

    let corpus = FuzzCorpus {
        schema_version: 1,
        target: target.as_str().to_owned(),
        rng_seed,
        source_sha256: hex_digest(&sha256_bytes(&seed)),
        cases,
    };
    fs::write(output_dir.join("corpus.json"), corpus.to_json_pretty())?;
    write_manifest(output_dir)?;
    Ok(corpus)
}

/// Minimizes a byte sequence while preserving an external predicate.
///
/// The algorithm is deterministic. The caller controls the predicate and
/// therefore what constitutes preservation of a crash or security regression.
pub fn minimize_with_oracle<F>(input: &[u8], mut preserves: F) -> Vec<u8>
where
    F: FnMut(&[u8]) -> bool,
{
    if !preserves(input) {
        return input.to_vec();
    }

    let mut current = input.to_vec();
    let mut granularity = 2_usize;

    while current.len() > 1 {
        let chunk = current.len().div_ceil(granularity);
        let mut reduced = false;
        let mut start = 0_usize;

        while start < current.len() {
            let end = start.saturating_add(chunk).min(current.len());
            let mut candidate = Vec::with_capacity(current.len() - (end - start));
            candidate.extend_from_slice(&current[..start]);
            candidate.extend_from_slice(&current[end..]);
            if !candidate.is_empty() && preserves(&candidate) {
                current = candidate;
                granularity = granularity.saturating_sub(1).max(2);
                reduced = true;
                break;
            }
            start = end;
        }

        if reduced {
            continue;
        }
        if granularity >= current.len() {
            break;
        }
        granularity = (granularity * 2).min(current.len());
    }

    for index in 0..current.len() {
        let original = current[index];
        for replacement in [0_u8, b'0', b'A', 0xff] {
            if replacement == original {
                continue;
            }
            current[index] = replacement;
            if preserves(&current) {
                break;
            }
            current[index] = original;
        }
    }
    current
}

/// Promotes a candidate into a permanent regression corpus without overwriting.
///
/// # Errors
///
/// Returns an error if the destination fixture or metadata already exists.
pub fn promote_regression_fixture(
    target: FuzzTarget,
    candidate: &Path,
    regression_root: &Path,
    note: &str,
) -> Result<RegressionFixture, FuzzError> {
    let bytes = fs::read(candidate)?;
    if bytes.len() > MAX_FUZZ_SEED_BYTES {
        return Err(FuzzError::SeedTooLarge(bytes.len()));
    }

    let hash = hex_digest(&sha256_bytes(&bytes));
    let target_dir = regression_root.join(target.as_str());
    fs::create_dir_all(&target_dir)?;

    let filename = format!("{}.bin", &hash[..16]);
    let metadata_name = format!("{}.json", &hash[..16]);
    let fixture_path = target_dir.join(&filename);
    let metadata_path = target_dir.join(&metadata_name);
    if fixture_path.exists() || metadata_path.exists() {
        return Err(FuzzError::RegressionExists(fixture_path));
    }

    fs::write(&fixture_path, &bytes)?;
    let fixture = RegressionFixture {
        schema_version: 1,
        target: target.as_str().to_owned(),
        filename,
        sha256: hash,
        source_name: candidate.file_name().map_or_else(
            || "candidate".to_owned(),
            |name| name.to_string_lossy().into_owned(),
        ),
        note: note.to_owned(),
    };
    fs::write(metadata_path, fixture.to_json_pretty())?;
    Ok(fixture)
}

fn mutate_case(
    target: FuzzTarget,
    seed: &[u8],
    index: usize,
    rng: &mut XorShift64,
) -> (Vec<u8>, String) {
    match index % 12 {
        0 => (Vec::new(), "empty".to_owned()),
        1 => (truncate(seed, 1), "truncate-one".to_owned()),
        2 => (truncate(seed, seed.len() / 2), "truncate-half".to_owned()),
        3 => (append(seed, &[0]), "append-zero".to_owned()),
        4 => (append(seed, &[0xff]), "append-ff".to_owned()),
        5 => (flip_random_bit(seed, rng), "seeded-bitflip".to_owned()),
        6 => (overwrite_random_byte(seed, rng, 0), "seeded-zero-byte".to_owned()),
        7 => (overwrite_random_byte(seed, rng, 0xff), "seeded-ff-byte".to_owned()),
        8 => structure_version_mutation(target, seed),
        9 => structure_length_mutation(target, seed),
        10 => structure_separator_mutation(target, seed),
        _ => (insert_random_byte(seed, rng), "seeded-byte-insert".to_owned()),
    }
}

fn structure_version_mutation(target: FuzzTarget, seed: &[u8]) -> (Vec<u8>, String) {
    let mut bytes = seed.to_vec();
    match target {
        FuzzTarget::AgentJson | FuzzTarget::PasswordManagerJson => {
            bytes.extend_from_slice(br#"{"version":18446744073709551615}"#);
            (bytes, "json-version-extreme".to_owned())
        }
        FuzzTarget::SyncHttp => {
            bytes.extend_from_slice(b"\r\nX-DragonForge-Base-Revision: 18446744073709551615");
            (bytes, "http-revision-extreme".to_owned())
        }
        FuzzTarget::WindowsPath => {
            bytes.extend_from_slice(b"/../CON.txt");
            (bytes, "path-traversal-device".to_owned())
        }
        _ => {
            if bytes.len() >= 8 {
                bytes[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
            } else {
                bytes.extend_from_slice(&u32::MAX.to_le_bytes());
            }
            (bytes, "binary-version-extreme".to_owned())
        }
    }
}

fn structure_length_mutation(target: FuzzTarget, seed: &[u8]) -> (Vec<u8>, String) {
    let mut bytes = seed.to_vec();
    match target {
        FuzzTarget::SyncHttp => {
            bytes.extend_from_slice(b"\r\nContent-Length: 18446744073709551615\r\n");
            (bytes, "http-length-extreme".to_owned())
        }
        FuzzTarget::AgentJson | FuzzTarget::PasswordManagerJson => {
            bytes.extend_from_slice(br#"{"length":18446744073709551615}"#);
            (bytes, "json-length-extreme".to_owned())
        }
        FuzzTarget::WindowsPath => {
            bytes.extend(std::iter::repeat_n(b'A', 260));
            (bytes, "path-long-segment".to_owned())
        }
        _ => {
            if bytes.len() >= 16 {
                bytes[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
            } else {
                bytes.extend_from_slice(&u64::MAX.to_le_bytes());
            }
            (bytes, "binary-length-extreme".to_owned())
        }
    }
}

fn structure_separator_mutation(target: FuzzTarget, seed: &[u8]) -> (Vec<u8>, String) {
    let mut bytes = seed.to_vec();
    match target {
        FuzzTarget::SyncHttp => {
            bytes.extend_from_slice(b"\r\n\r\n\r\n");
            (bytes, "http-extra-header-boundary".to_owned())
        }
        FuzzTarget::AgentJson | FuzzTarget::PasswordManagerJson => {
            bytes.extend_from_slice(b"}{");
            (bytes, "json-concatenated-object".to_owned())
        }
        FuzzTarget::WindowsPath => {
            bytes.extend_from_slice(b"//..//");
            (bytes, "path-empty-traversal-segments".to_owned())
        }
        _ => {
            bytes.splice(0..0, [0_u8; 8]);
            (bytes, "binary-zero-prefix".to_owned())
        }
    }
}

fn truncate(seed: &[u8], length: usize) -> Vec<u8> {
    seed[..length.min(seed.len())].to_vec()
}

fn append(seed: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(seed.len() + suffix.len());
    bytes.extend_from_slice(seed);
    bytes.extend_from_slice(suffix);
    bytes
}

fn flip_random_bit(seed: &[u8], rng: &mut XorShift64) -> Vec<u8> {
    let mut bytes = ensure_nonempty(seed);
    let index = rng.index(bytes.len());
    let bit = 1_u8 << (rng.next_u64() % 8);
    bytes[index] ^= bit;
    bytes
}

fn overwrite_random_byte(seed: &[u8], rng: &mut XorShift64, value: u8) -> Vec<u8> {
    let mut bytes = ensure_nonempty(seed);
    let index = rng.index(bytes.len());
    bytes[index] = value;
    bytes
}

fn insert_random_byte(seed: &[u8], rng: &mut XorShift64) -> Vec<u8> {
    let mut bytes = seed.to_vec();
    let index = if bytes.is_empty() {
        0
    } else {
        rng.index(bytes.len() + 1)
    };
    bytes.insert(index, u8::try_from(rng.next_u64() & 0xff).unwrap_or(0));
    bytes
}

fn ensure_nonempty(seed: &[u8]) -> Vec<u8> {
    if seed.is_empty() {
        vec![0]
    } else {
        seed.to_vec()
    }
}

fn write_manifest(output_dir: &Path) -> Result<(), FuzzError> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(output_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name != "SHA256SUMS" {
                entries.push((name, fs::read(path)?));
            }
        }
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let mut manifest = String::new();
    for (name, bytes) in entries {
        let _ = writeln!(manifest, "{}  {}", hex_digest(&sha256_bytes(&bytes)), name);
    }
    fs::write(output_dir.join("SHA256SUMS"), manifest)?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x9e37_79b9_7f4a_7c15
            } else {
                seed
            },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.state = value;
        value
    }

    fn index(&mut self, length: usize) -> usize {
        let length_u64 = u64::try_from(length).unwrap_or(u64::MAX);
        usize::try_from(self.next_u64() % length_u64).unwrap_or(0)
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
        FuzzTarget, generate_fuzz_corpus, minimize_with_oracle, promote_regression_fixture,
    };

    fn temp_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "dfstl-fuzz-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn deterministic_corpus_repeats_for_same_seed() {
        let seed_path = temp_path("seed");
        let first = temp_path("first");
        let second = temp_path("second");
        fs::write(&seed_path, b"DragonForge").expect("seed");

        let one = generate_fuzz_corpus(FuzzTarget::AgentJson, &seed_path, &first, 42, 24)
            .expect("first");
        let two = generate_fuzz_corpus(FuzzTarget::AgentJson, &seed_path, &second, 42, 24)
            .expect("second");

        assert_eq!(one.cases, two.cases);
        assert_eq!(one.source_sha256, two.source_sha256);

        fs::remove_file(seed_path).expect("cleanup seed");
        fs::remove_dir_all(first).expect("cleanup first");
        fs::remove_dir_all(second).expect("cleanup second");
    }

    #[test]
    fn all_fuzz_targets_parse_and_generate_structure_cases() {
        for target in FuzzTarget::all() {
            assert_eq!(FuzzTarget::parse(target.as_str()).expect("parse"), target);
        }
    }

    #[test]
    fn minimizer_preserves_oracle_and_reduces_input() {
        let input = b"AAAA-CRASH-BBBB";
        let minimized = minimize_with_oracle(input, |bytes| {
            bytes.windows(5).any(|window| window == b"CRASH")
        });
        assert!(minimized.windows(5).any(|window| window == b"CRASH"));
        assert!(minimized.len() < input.len());
    }

    #[test]
    fn promotion_is_hash_named_and_refuses_overwrite() {
        let candidate = temp_path("candidate");
        let regression = temp_path("regression");
        fs::write(&candidate, b"regression-case").expect("candidate");

        let fixture = promote_regression_fixture(
            FuzzTarget::SyncHttp,
            &candidate,
            &regression,
            "synthetic regression",
        )
        .expect("promote");
        assert!(fixture.filename.ends_with(".bin"));
        assert!(
            regression
                .join("sync-http")
                .join(&fixture.filename)
                .is_file()
        );
        assert!(
            promote_regression_fixture(
                FuzzTarget::SyncHttp,
                &candidate,
                &regression,
                "duplicate"
            )
            .is_err()
        );

        fs::remove_file(candidate).expect("cleanup candidate");
        fs::remove_dir_all(regression).expect("cleanup regression");
    }
}
