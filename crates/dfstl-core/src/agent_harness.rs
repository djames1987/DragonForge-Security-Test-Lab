use std::fmt;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::hash::{hex_digest, sha256_bytes};

pub const AGENT_PROTOCOL_MAJOR: u16 = 1;
pub const AGENT_PROTOCOL_MINOR: u16 = 1;
pub const MAX_CLOCK_SKEW_MS: u64 = 60_000;
pub const MAX_WIRE_BYTES: usize = 16 * 1024;
pub const SESSION_KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 16;
pub const MAX_ATTACK_CASES: usize = 32;

const CONNECT_TIMEOUT: Duration = Duration::from_millis(750);
const IO_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug)]
pub enum AgentHarnessError {
    Io(io::Error),
    MissingRuntimeFile(PathBuf),
    MissingCredentialFile(PathBuf),
    SymlinkRejected(PathBuf),
    MalformedRuntime,
    IncompatibleRuntime,
    InvalidCredential,
    NonLoopbackTarget,
    OutputExists(PathBuf),
}

impl fmt::Display for AgentHarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => f.write_str("agent harness I/O failure"),
            Self::MissingRuntimeFile(path) => {
                write!(f, "agent runtime file is missing: {}", path.display())
            }
            Self::MissingCredentialFile(path) => {
                write!(f, "agent credential file is missing: {}", path.display())
            }
            Self::SymlinkRejected(path) => {
                write!(f, "agent runtime symlink is rejected: {}", path.display())
            }
            Self::MalformedRuntime => f.write_str("agent runtime descriptor is malformed"),
            Self::IncompatibleRuntime => f.write_str("agent runtime descriptor is incompatible"),
            Self::InvalidCredential => f.write_str("agent session credential is invalid"),
            Self::NonLoopbackTarget => f.write_str("agent harness target is not IPv4 loopback"),
            Self::OutputExists(path) => {
                write!(f, "agent harness output already exists: {}", path.display())
            }
        }
    }
}

impl std::error::Error for AgentHarnessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for AgentHarnessError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRuntime {
    pub format_version: u16,
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub port: u16,
    pub pid: u32,
    pub started_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackOutcome {
    Rejected,
    Accepted,
    NoResponse,
    TransportError,
}

impl AttackOutcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rejected => "rejected",
            Self::Accepted => "accepted",
            Self::NoResponse => "no-response",
            Self::TransportError => "transport-error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackCaseResult {
    pub id: String,
    pub expected: String,
    pub outcome: AttackOutcome,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentAttackReport {
    pub schema_version: u32,
    pub runtime: AgentRuntime,
    pub cases: Vec<AttackCaseResult>,
}

impl AgentAttackReport {
    #[must_use]
    pub fn all_expected(&self) -> bool {
        self.cases.iter().all(|case| match case.expected.as_str() {
            "rejected" => matches!(case.outcome, AttackOutcome::Rejected | AttackOutcome::NoResponse),
            "accepted" => matches!(case.outcome, AttackOutcome::Accepted),
            _ => false,
        })
    }

    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(output, "{{");
        let _ = writeln!(output, "  \"schema_version\": {},", self.schema_version);
        let _ = writeln!(output, "  \"runtime\": {{");
        let _ = writeln!(
            output,
            "    \"protocol_major\": {},",
            self.runtime.protocol_major
        );
        let _ = writeln!(
            output,
            "    \"protocol_minor\": {},",
            self.runtime.protocol_minor
        );
        let _ = writeln!(output, "    \"port\": {},", self.runtime.port);
        let _ = writeln!(output, "    \"pid\": {}", self.runtime.pid);
        let _ = writeln!(output, "  }},");
        let _ = writeln!(output, "  \"all_expected\": {},", self.all_expected());
        let _ = writeln!(output, "  \"cases\": [");
        for (index, case) in self.cases.iter().enumerate() {
            let comma = if index + 1 == self.cases.len() { "" } else { "," };
            let _ = writeln!(output, "    {{");
            let _ = writeln!(output, "      \"id\": \"{}\",", json_escape(&case.id));
            let _ = writeln!(
                output,
                "      \"expected\": \"{}\",",
                json_escape(&case.expected)
            );
            let _ = writeln!(
                output,
                "      \"outcome\": \"{}\",",
                case.outcome.as_str()
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
        let _ = writeln!(output, "DragonForge Agent attack harness");
        let _ = writeln!(
            output,
            "Protocol: {}.{}",
            self.runtime.protocol_major, self.runtime.protocol_minor
        );
        let _ = writeln!(output, "Port: {}", self.runtime.port);
        let _ = writeln!(output, "Cases: {}", self.cases.len());
        for case in &self.cases {
            let _ = writeln!(
                output,
                "{}  expected={} outcome={}  {}",
                case.id,
                case.expected,
                case.outcome.as_str(),
                case.detail
            );
        }
        output
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeMutationCase {
    pub id: String,
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeMutationCorpus {
    pub schema_version: u32,
    pub cases: Vec<RuntimeMutationCase>,
}

impl RuntimeMutationCorpus {
    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(output, "{{");
        let _ = writeln!(output, "  \"schema_version\": {},", self.schema_version);
        let _ = writeln!(output, "  \"cases\": [");
        for (index, case) in self.cases.iter().enumerate() {
            let comma = if index + 1 == self.cases.len() { "" } else { "," };
            let _ = writeln!(
                output,
                "    {{\"id\":\"{}\",\"path\":\"{}\",\"sha256\":\"{}\"}}{comma}",
                json_escape(&case.id),
                json_escape(&case.path),
                case.sha256
            );
        }
        let _ = writeln!(output, "  ]");
        let _ = writeln!(output, "}}");
        output
    }
}

/// Runs bounded black-box attacks against one explicit DragonForge Agent runtime.
///
/// # Errors
///
/// Returns an error when runtime metadata or the credential cannot be read,
/// validated, or connected to over IPv4 loopback.
pub fn run_agent_attack_harness(runtime_dir: &Path) -> Result<AgentAttackReport, AgentHarnessError> {
    let runtime_path = runtime_dir.join("agent-runtime.json");
    let credential_path = runtime_dir.join("agent-session.key");
    validate_regular_file(&runtime_path, true)?;
    validate_regular_file(&credential_path, false)?;

    let runtime_text = fs::read_to_string(&runtime_path)?;
    if runtime_text.len() >= MAX_WIRE_BYTES {
        return Err(AgentHarnessError::MalformedRuntime);
    }
    let runtime = parse_runtime(&runtime_text)?;
    if runtime.format_version != 1 || runtime.protocol_major != AGENT_PROTOCOL_MAJOR {
        return Err(AgentHarnessError::IncompatibleRuntime);
    }

    let key_text = fs::read_to_string(&credential_path)?;
    let key = base64_decode(key_text.trim()).ok_or(AgentHarnessError::InvalidCredential)?;
    if key.len() != SESSION_KEY_BYTES {
        return Err(AgentHarnessError::InvalidCredential);
    }

    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, runtime.port);
    if !address.ip().is_loopback() {
        return Err(AgentHarnessError::NonLoopbackTarget);
    }

    let now = now_ms();
    let mut cases = Vec::new();

    cases.push(send_raw_case(
        address,
        "malformed-json",
        "rejected",
        b"{not-json}\n",
    ));

    let oversized = vec![b'A'; MAX_WIRE_BYTES];
    cases.push(send_raw_case(
        address,
        "oversized-message",
        "rejected",
        &oversized,
    ));

    let nonce = deterministic_nonce(1);
    let unsigned = RequestSpec::new(1001, now, nonce.clone());
    cases.push(send_request_case(
        address,
        "invalid-hmac",
        "rejected",
        &unsigned,
        "00".repeat(32),
    ));

    let mut wrong_source = RequestSpec::new(1002, now, deterministic_nonce(2));
    wrong_source.source = "security-scanner".to_owned();
    cases.push(send_signed_case(
        address,
        "wrong-source",
        "rejected",
        &wrong_source,
        &key,
    ));

    let mut wrong_protocol = RequestSpec::new(1003, now, deterministic_nonce(3));
    wrong_protocol.protocol_major = AGENT_PROTOCOL_MAJOR.saturating_add(1);
    cases.push(send_signed_case(
        address,
        "wrong-protocol-major",
        "rejected",
        &wrong_protocol,
        &key,
    ));

    let stale = RequestSpec::new(
        1004,
        now.saturating_sub(MAX_CLOCK_SKEW_MS.saturating_add(1)),
        deterministic_nonce(4),
    );
    cases.push(send_signed_case(
        address,
        "stale-timestamp",
        "rejected",
        &stale,
        &key,
    ));

    let future = RequestSpec::new(
        1005,
        now.saturating_add(MAX_CLOCK_SKEW_MS.saturating_add(1)),
        deterministic_nonce(5),
    );
    cases.push(send_signed_case(
        address,
        "future-timestamp",
        "rejected",
        &future,
        &key,
    ));

    let invalid_nonce = RequestSpec::new(1006, now, "AA==".to_owned());
    cases.push(send_signed_case(
        address,
        "invalid-nonce-length",
        "rejected",
        &invalid_nonce,
        &key,
    ));

    let valid = RequestSpec::new(1007, now_ms(), deterministic_nonce(7));
    cases.push(send_signed_case(
        address,
        "valid-health",
        "accepted",
        &valid,
        &key,
    ));
    cases.push(send_signed_case(
        address,
        "replayed-nonce",
        "rejected",
        &valid,
        &key,
    ));

    if cases.len() > MAX_ATTACK_CASES {
        cases.truncate(MAX_ATTACK_CASES);
    }

    Ok(AgentAttackReport {
        schema_version: 1,
        runtime,
        cases,
    })
}

/// Generates a disposable runtime-file mutation corpus without changing the live
/// Agent runtime directory.
///
/// # Errors
///
/// Returns an error if the source runtime cannot be read or the output already
/// exists.
pub fn generate_runtime_mutation_corpus(
    runtime_dir: &Path,
    output_dir: &Path,
) -> Result<RuntimeMutationCorpus, AgentHarnessError> {
    if output_dir.exists() {
        return Err(AgentHarnessError::OutputExists(output_dir.to_path_buf()));
    }

    let runtime_path = runtime_dir.join("agent-runtime.json");
    let credential_path = runtime_dir.join("agent-session.key");
    validate_regular_file(&runtime_path, true)?;
    validate_regular_file(&credential_path, false)?;

    let runtime = fs::read(&runtime_path)?;
    let credential = fs::read(&credential_path)?;

    fs::create_dir(output_dir)?;
    let mut cases = Vec::new();
    write_runtime_case(
        output_dir,
        &mut cases,
        "descriptor-empty",
        "descriptor-empty/agent-runtime.json",
        b"",
    )?;
    write_runtime_case(
        output_dir,
        &mut cases,
        "descriptor-malformed",
        "descriptor-malformed/agent-runtime.json",
        b"{",
    )?;
    write_runtime_case(
        output_dir,
        &mut cases,
        "descriptor-oversized",
        "descriptor-oversized/agent-runtime.json",
        &vec![b'X'; MAX_WIRE_BYTES + 1],
    )?;
    write_runtime_case(
        output_dir,
        &mut cases,
        "credential-empty",
        "credential-empty/agent-session.key",
        b"",
    )?;
    write_runtime_case(
        output_dir,
        &mut cases,
        "credential-malformed-base64",
        "credential-malformed-base64/agent-session.key",
        b"not-base64!\n",
    )?;
    write_runtime_case(
        output_dir,
        &mut cases,
        "credential-wrong-length",
        "credential-wrong-length/agent-session.key",
        b"AA==\n",
    )?;

    let baseline = output_dir.join("baseline");
    fs::create_dir(&baseline)?;
    fs::write(baseline.join("agent-runtime.json"), &runtime)?;
    fs::write(baseline.join("agent-session.key"), &credential)?;

    let corpus = RuntimeMutationCorpus {
        schema_version: 1,
        cases,
    };
    fs::write(output_dir.join("runtime-mutations.json"), corpus.to_json_pretty())?;
    Ok(corpus)
}

fn validate_regular_file(path: &Path, runtime: bool) -> Result<(), AgentHarnessError> {
    if !path.exists() {
        return if runtime {
            Err(AgentHarnessError::MissingRuntimeFile(path.to_path_buf()))
        } else {
            Err(AgentHarnessError::MissingCredentialFile(path.to_path_buf()))
        };
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(AgentHarnessError::SymlinkRejected(path.to_path_buf()));
    }
    if !metadata.is_file() {
        return if runtime {
            Err(AgentHarnessError::MissingRuntimeFile(path.to_path_buf()))
        } else {
            Err(AgentHarnessError::MissingCredentialFile(path.to_path_buf()))
        };
    }
    Ok(())
}

fn parse_runtime(text: &str) -> Result<AgentRuntime, AgentHarnessError> {
    Ok(AgentRuntime {
        format_version: json_u64(text, "format_version")
            .and_then(|value| u16::try_from(value).ok())
            .ok_or(AgentHarnessError::MalformedRuntime)?,
        protocol_major: json_u64(text, "protocol_major")
            .and_then(|value| u16::try_from(value).ok())
            .ok_or(AgentHarnessError::MalformedRuntime)?,
        protocol_minor: json_u64(text, "protocol_minor")
            .and_then(|value| u16::try_from(value).ok())
            .ok_or(AgentHarnessError::MalformedRuntime)?,
        port: json_u64(text, "port")
            .and_then(|value| u16::try_from(value).ok())
            .filter(|value| *value != 0)
            .ok_or(AgentHarnessError::MalformedRuntime)?,
        pid: json_u64(text, "pid")
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(AgentHarnessError::MalformedRuntime)?,
        started_at_ms: json_u64(text, "started_at_ms").ok_or(AgentHarnessError::MalformedRuntime)?,
    })
}

fn json_u64(text: &str, key: &str) -> Option<u64> {
    let pattern = format!("\"{key}\"");
    let start = text.find(&pattern)? + pattern.len();
    let suffix = &text[start..];
    let colon = suffix.find(':')?;
    let value = suffix[colon + 1..].trim_start();
    let end = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    value[..end].parse().ok()
}

#[derive(Debug, Clone)]
struct RequestSpec {
    protocol_major: u16,
    protocol_minor: u16,
    request_id: u64,
    source: String,
    action: String,
    timestamp_ms: u64,
    nonce_b64: String,
}

impl RequestSpec {
    fn new(request_id: u64, timestamp_ms: u64, nonce_b64: String) -> Self {
        Self {
            protocol_major: AGENT_PROTOCOL_MAJOR,
            protocol_minor: AGENT_PROTOCOL_MINOR,
            request_id,
            source: "security-center".to_owned(),
            action: "health".to_owned(),
            timestamp_ms,
            nonce_b64,
        }
    }

    fn message(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}",
            self.protocol_major,
            self.protocol_minor,
            self.request_id,
            self.source,
            self.action,
            self.timestamp_ms,
            self.nonce_b64
        )
    }

    fn json(&self, auth_tag_hex: &str) -> String {
        format!(
            concat!(
                "{{\"protocol_major\":{},\"protocol_minor\":{},",
                "\"request_id\":{},\"source\":\"{}\",",
                "\"action\":\"{}\",\"timestamp_ms\":{},",
                "\"nonce_b64\":\"{}\",\"auth_tag_hex\":\"{}\"}}\n"
            ),
            self.protocol_major,
            self.protocol_minor,
            self.request_id,
            json_escape(&self.source),
            json_escape(&self.action),
            self.timestamp_ms,
            json_escape(&self.nonce_b64),
            auth_tag_hex
        )
    }
}

fn send_signed_case(
    address: SocketAddrV4,
    id: &str,
    expected: &str,
    request: &RequestSpec,
    key: &[u8],
) -> AttackCaseResult {
    let tag = hex_digest(&hmac_sha256(key, request.message().as_bytes()));
    send_request_case(address, id, expected, request, tag)
}

fn send_request_case(
    address: SocketAddrV4,
    id: &str,
    expected: &str,
    request: &RequestSpec,
    tag: String,
) -> AttackCaseResult {
    send_raw_case(address, id, expected, request.json(&tag).as_bytes())
}

fn send_raw_case(
    address: SocketAddrV4,
    id: &str,
    expected: &str,
    bytes: &[u8],
) -> AttackCaseResult {
    match send_wire(address, bytes) {
        Ok(Some(response)) => {
            let ok = json_bool(&response, "ok").unwrap_or(false);
            AttackCaseResult {
                id: id.to_owned(),
                expected: expected.to_owned(),
                outcome: if ok {
                    AttackOutcome::Accepted
                } else {
                    AttackOutcome::Rejected
                },
                detail: if ok {
                    "agent returned an accepted response".to_owned()
                } else {
                    "agent returned an authenticated/generic rejection response".to_owned()
                },
            }
        }
        Ok(None) => AttackCaseResult {
            id: id.to_owned(),
            expected: expected.to_owned(),
            outcome: AttackOutcome::NoResponse,
            detail: "connection closed or timed out without a response".to_owned(),
        },
        Err(_) => AttackCaseResult {
            id: id.to_owned(),
            expected: expected.to_owned(),
            outcome: AttackOutcome::TransportError,
            detail: "loopback transport failed".to_owned(),
        },
    }
}

fn send_wire(address: SocketAddrV4, bytes: &[u8]) -> io::Result<Option<String>> {
    let mut stream = TcpStream::connect_timeout(&address.into(), CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.write_all(bytes)?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    match reader
        .by_ref()
        .take(MAX_WIRE_BYTES as u64)
        .read_line(&mut line)
    {
        Ok(0) => Ok(None),
        Ok(count) if count >= MAX_WIRE_BYTES => Ok(None),
        Ok(_) => Ok(Some(line)),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn json_bool(text: &str, key: &str) -> Option<bool> {
    let pattern = format!("\"{key}\"");
    let start = text.find(&pattern)? + pattern.len();
    let suffix = &text[start..];
    let colon = suffix.find(':')?;
    let value = suffix[colon + 1..].trim_start();
    if value.starts_with("true") {
        Some(true)
    } else if value.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn deterministic_nonce(seed: u8) -> String {
    base64_encode(&[seed; NONCE_BYTES])
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_block = [0_u8; 64];
    if key.len() > 64 {
        key_block[..32].copy_from_slice(&sha256_bytes(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner = [0_u8; 64];
    let mut outer = [0_u8; 64];
    for index in 0..64 {
        inner[index] = key_block[index] ^ 0x36;
        outer[index] = key_block[index] ^ 0x5c;
    }

    let mut inner_data = Vec::with_capacity(64 + message.len());
    inner_data.extend_from_slice(&inner);
    inner_data.extend_from_slice(message);
    let inner_hash = sha256_bytes(&inner_data);

    let mut outer_data = Vec::with_capacity(96);
    outer_data.extend_from_slice(&outer);
    outer_data.extend_from_slice(&inner_hash);
    sha256_bytes(&outer_data)
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = u32::from(chunk[0]);
        let second = u32::from(*chunk.get(1).unwrap_or(&0));
        let third = u32::from(*chunk.get(2).unwrap_or(&0));
        let value = (first << 16) | (second << 8) | third;
        output.push(char::from(TABLE[((value >> 18) & 0x3f) as usize]));
        output.push(char::from(TABLE[((value >> 12) & 0x3f) as usize]));
        if chunk.len() > 1 {
            output.push(char::from(TABLE[((value >> 6) & 0x3f) as usize]));
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(char::from(TABLE[(value & 0x3f) as usize]));
        } else {
            output.push('=');
        }
    }
    output
}

fn base64_decode(value: &str) -> Option<Vec<u8>> {
    if value.len() % 4 != 0 {
        return None;
    }
    let mut output = Vec::with_capacity(value.len() / 4 * 3);
    for chunk in value.as_bytes().chunks_exact(4) {
        let a = base64_value(chunk[0])?;
        let b = base64_value(chunk[1])?;
        let c = if chunk[2] == b'=' { 0 } else { base64_value(chunk[2])? };
        let d = if chunk[3] == b'=' { 0 } else { base64_value(chunk[3])? };
        let value = (u32::from(a) << 18)
            | (u32::from(b) << 12)
            | (u32::from(c) << 6)
            | u32::from(d);
        output.push(((value >> 16) & 0xff) as u8);
        if chunk[2] != b'=' {
            output.push(((value >> 8) & 0xff) as u8);
        }
        if chunk[3] != b'=' {
            output.push((value & 0xff) as u8);
        }
    }
    Some(output)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn write_runtime_case(
    output_dir: &Path,
    cases: &mut Vec<RuntimeMutationCase>,
    id: &str,
    relative: &str,
    bytes: &[u8],
) -> Result<(), AgentHarnessError> {
    let path = output_dir.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, bytes)?;
    cases.push(RuntimeMutationCase {
        id: id.to_owned(),
        path: relative.replace('\\', "/"),
        sha256: hex_digest(&sha256_bytes(bytes)),
    });
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

    use super::{
        AgentAttackReport, AgentRuntime, AttackCaseResult, AttackOutcome, RuntimeMutationCorpus,
        base64_decode, base64_encode, generate_runtime_mutation_corpus, hmac_sha256,
    };
    use crate::hash::hex_digest;

    fn temp_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "dfstl-agent-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn base64_round_trip_matches_agent_key_shape() {
        let key = [7_u8; 32];
        let encoded = base64_encode(&key);
        assert_eq!(base64_decode(&encoded).expect("decode"), key);
    }

    #[test]
    fn hmac_matches_rfc4231_vector() {
        let key = [0x0b_u8; 20];
        let digest = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            hex_digest(&digest),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn expected_outcome_logic_treats_no_response_as_rejection() {
        let report = AgentAttackReport {
            schema_version: 1,
            runtime: AgentRuntime {
                format_version: 1,
                protocol_major: 1,
                protocol_minor: 1,
                port: 1234,
                pid: 1,
                started_at_ms: 1,
            },
            cases: vec![AttackCaseResult {
                id: "malformed".to_owned(),
                expected: "rejected".to_owned(),
                outcome: AttackOutcome::NoResponse,
                detail: "closed".to_owned(),
            }],
        };
        assert!(report.all_expected());
    }

    #[test]
    fn runtime_mutation_corpus_never_modifies_source() {
        let root = temp_path("runtime");
        let output = temp_path("mutations");
        fs::create_dir(&root).expect("root");
        let runtime = br#"{"format_version":1,"protocol_major":1,"protocol_minor":1,"port":1234,"pid":7,"started_at_ms":9}"#;
        let credential = format!("{}\n", base64_encode(&[9_u8; 32]));
        fs::write(root.join("agent-runtime.json"), runtime).expect("runtime");
        fs::write(root.join("agent-session.key"), &credential).expect("credential");

        let runtime_before = fs::read(root.join("agent-runtime.json")).expect("read");
        let key_before = fs::read(root.join("agent-session.key")).expect("read");
        let corpus: RuntimeMutationCorpus =
            generate_runtime_mutation_corpus(&root, &output).expect("corpus");

        assert_eq!(corpus.cases.len(), 6);
        assert_eq!(
            fs::read(root.join("agent-runtime.json")).expect("runtime"),
            runtime_before
        );
        assert_eq!(
            fs::read(root.join("agent-session.key")).expect("credential"),
            key_before
        );

        fs::remove_dir_all(root).expect("cleanup root");
        fs::remove_dir_all(output).expect("cleanup output");
    }
}
