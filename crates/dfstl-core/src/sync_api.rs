use std::fmt;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::hash::{hex_digest, sha256_bytes};

pub const SYNC_PROTOCOL_VERSION: u16 = 2;
pub const MAX_CAPTURE_BYTES: usize = 2 * 1024 * 1024;
pub const SYNC_BLOB_BYTES: usize = 64 * 1024 * 1024;
pub const SYNC_REQUEST_LIMIT_BYTES: usize = SYNC_BLOB_BYTES + 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_millis(750);
const IO_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug)]
pub enum SyncApiError {
    Io(io::Error),
    InvalidBaseUrl,
    NonLoopbackTarget,
    CaptureTooLarge,
    InvalidCapture,
    OutputExists(PathBuf),
}

impl fmt::Display for SyncApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => f.write_str("sync API harness I/O failure"),
            Self::InvalidBaseUrl => f.write_str("sync API base URL is invalid"),
            Self::NonLoopbackTarget => {
                f.write_str("sync API live harness only permits IPv4 loopback")
            }
            Self::CaptureTooLarge => f.write_str("captured request exceeds the safe size limit"),
            Self::InvalidCapture => f.write_str("captured HTTP request is malformed"),
            Self::OutputExists(path) => {
                write!(f, "sync API mutation output already exists: {}", path.display())
            }
        }
    }
}

impl std::error::Error for SyncApiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for SyncApiError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveProbeCase {
    pub id: String,
    pub expected: String,
    pub status: Option<u16>,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncApiProbeReport {
    pub schema_version: u32,
    pub protocol_version: u16,
    pub endpoint: String,
    pub cases: Vec<LiveProbeCase>,
}

impl SyncApiProbeReport {
    #[must_use]
    pub fn all_expected(&self) -> bool {
        self.cases.iter().all(|case| case.passed)
    }

    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(output, "{{");
        let _ = writeln!(output, "  \"schema_version\": {},", self.schema_version);
        let _ = writeln!(
            output,
            "  \"protocol_version\": {},",
            self.protocol_version
        );
        let _ = writeln!(
            output,
            "  \"endpoint\": \"{}\",",
            json_escape(&self.endpoint)
        );
        let _ = writeln!(output, "  \"all_expected\": {},", self.all_expected());
        let _ = writeln!(output, "  \"cases\": [");
        for (index, case) in self.cases.iter().enumerate() {
            let comma = if index + 1 == self.cases.len() { "" } else { "," };
            let status = case
                .status
                .map_or_else(|| "null".to_owned(), |value| value.to_string());
            let _ = writeln!(
                output,
                concat!(
                    "    {{\"id\":\"{}\",\"expected\":\"{}\",",
                    "\"status\":{},\"passed\":{},\"detail\":\"{}\"}}{}"
                ),
                json_escape(&case.id),
                json_escape(&case.expected),
                status,
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
pub struct RequestMutationCase {
    pub id: String,
    pub filename: String,
    pub sha256: String,
    pub expected_behavior: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestMutationCorpus {
    pub schema_version: u32,
    pub source_sha256: String,
    pub cases: Vec<RequestMutationCase>,
}

impl RequestMutationCorpus {
    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(output, "{{");
        let _ = writeln!(output, "  \"schema_version\": {},", self.schema_version);
        let _ = writeln!(
            output,
            "  \"source_sha256\": \"{}\",",
            self.source_sha256
        );
        let _ = writeln!(output, "  \"cases\": [");
        for (index, case) in self.cases.iter().enumerate() {
            let comma = if index + 1 == self.cases.len() { "" } else { "," };
            let _ = writeln!(
                output,
                concat!(
                    "    {{\"id\":\"{}\",\"filename\":\"{}\",",
                    "\"sha256\":\"{}\",\"expected_behavior\":\"{}\"}}{}"
                ),
                json_escape(&case.id),
                json_escape(&case.filename),
                case.sha256,
                json_escape(&case.expected_behavior),
                comma
            );
        }
        let _ = writeln!(output, "  ]");
        let _ = writeln!(output, "}}");
        output
    }
}

type HttpResponse = (u16, Vec<(String, String)>, Vec<u8>);

#[derive(Debug, Clone)]
struct ParsedRequest {
    request_line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Runs bounded, non-state-changing probes against one explicit local sync server.
///
/// # Errors
///
/// Returns an error when the URL is invalid, non-loopback, or transport setup fails.
pub fn run_sync_api_probe(base_url: &str) -> Result<SyncApiProbeReport, SyncApiError> {
    let endpoint = parse_loopback_base_url(base_url)?;
    let cases = vec![
        probe_health(endpoint)?,
        probe(
            endpoint,
            "missing-auth-devices",
            "GET",
            "/v1/devices",
            &[],
            &[],
            &[401],
        )?,
        probe(
            endpoint,
            "malformed-bearer-devices",
            "GET",
            "/v1/devices",
            &[("Authorization", "Bearer not-a-valid-token")],
            &[],
            &[401],
        )?,
        probe(
            endpoint,
            "bad-admin-provision",
            "POST",
            "/v1/accounts",
            &[("X-DragonForge-Admin-Token", "invalid-admin-token")],
            &[],
            &[403],
        )?,
        probe(
            endpoint,
            "unknown-route",
            "GET",
            "/v1/does-not-exist",
            &[],
            &[],
            &[404],
        )?,
        probe(
            endpoint,
            "wrong-method-health",
            "POST",
            "/v1/health",
            &[],
            &[],
            &[405],
        )?,
        probe(
            endpoint,
            "malformed-recovery-json",
            "POST",
            "/v1/recovery/begin",
            &[("Content-Type", "application/json")],
            b"{",
            &[400, 422],
        )?,
        probe_declared_oversize(endpoint, "oversized-request", "/v1/recovery/begin")?,
    ];

    Ok(SyncApiProbeReport {
        schema_version: 1,
        protocol_version: SYNC_PROTOCOL_VERSION,
        endpoint: base_url.to_owned(),
        cases,
    })
}

/// Generates an offline mutation corpus from a captured HTTP request.
///
/// No generated request is transmitted by this function.
///
/// # Errors
///
/// Returns an error for malformed/oversized input or an existing output directory.
pub fn generate_sync_request_mutations(
    capture: &Path,
    output_dir: &Path,
) -> Result<RequestMutationCorpus, SyncApiError> {
    if output_dir.exists() {
        return Err(SyncApiError::OutputExists(output_dir.to_path_buf()));
    }

    let bytes = fs::read(capture)?;
    if bytes.len() > MAX_CAPTURE_BYTES {
        return Err(SyncApiError::CaptureTooLarge);
    }
    let parsed = parse_capture(&bytes)?;
    fs::create_dir(output_dir)?;

    let mut cases = Vec::new();
    write_auth_device_mutations(output_dir, &parsed, &mut cases)?;
    write_revision_body_mutations(output_dir, &parsed, &mut cases)?;
    write_enrollment_recovery_mutations(output_dir, &parsed, &mut cases)?;

    let corpus = RequestMutationCorpus {
        schema_version: 1,
        source_sha256: hex_digest(&sha256_bytes(&bytes)),
        cases,
    };
    fs::write(
        output_dir.join("sync-api-mutations.json"),
        corpus.to_json_pretty(),
    )?;
    write_manifest(output_dir)?;
    Ok(corpus)
}

fn write_auth_device_mutations(
    output_dir: &Path,
    parsed: &ParsedRequest,
    cases: &mut Vec<RequestMutationCase>,
) -> Result<(), SyncApiError> {
    write_mutation(
        output_dir,
        cases,
        "exact-replay",
        "01-exact-replay.http",
        &serialize_request(parsed),
        concat!(
            "state-changing replay must not bypass revision/recovery protections; ",
            "ordinary signed GET replay is freshness-bounded by the current protocol"
        ),
    )?;

    let mut no_auth = parsed.clone();
    remove_header(&mut no_auth, "authorization");
    write_mutation(
        output_dir,
        cases,
        "missing-bearer",
        "02-missing-bearer.http",
        &serialize_request(&no_auth),
        "must be rejected when account authentication is required",
    )?;

    let mut wrong_auth = parsed.clone();
    set_header(
        &mut wrong_auth,
        "Authorization",
        &format!("Bearer {}", "0".repeat(64)),
    );
    write_mutation(
        output_dir,
        cases,
        "wrong-bearer",
        "03-wrong-bearer.http",
        &serialize_request(&wrong_auth),
        "must be rejected as unauthorized",
    )?;

    let mut wrong_device = parsed.clone();
    set_header(
        &mut wrong_device,
        "X-DragonForge-Device-Id",
        "00000000-0000-0000-0000-000000000001",
    );
    write_mutation(
        output_dir,
        cases,
        "device-id-swap",
        "04-device-id-swap.http",
        &serialize_request(&wrong_device),
        "must fail device authorization/signature binding",
    )?;

    let mut stale_timestamp = parsed.clone();
    set_header(
        &mut stale_timestamp,
        "X-DragonForge-Device-Timestamp",
        "1",
    );
    write_mutation(
        output_dir,
        cases,
        "stale-device-timestamp",
        "05-stale-device-timestamp.http",
        &serialize_request(&stale_timestamp),
        "must be rejected outside the five-minute freshness window",
    )?;

    let mut signature_flip = parsed.clone();
    set_header(
        &mut signature_flip,
        "X-DragonForge-Device-Signature",
        "00",
    );
    write_mutation(
        output_dir,
        cases,
        "invalid-device-signature",
        "06-invalid-device-signature.http",
        &serialize_request(&signature_flip),
        "must fail ML-DSA request authorization",
    )
}

fn write_revision_body_mutations(
    output_dir: &Path,
    parsed: &ParsedRequest,
    cases: &mut Vec<RequestMutationCase>,
) -> Result<(), SyncApiError> {
    let mut revision = parsed.clone();
    set_header(&mut revision, "X-DragonForge-Base-Revision", "0");
    write_mutation(
        output_dir,
        cases,
        "base-revision-zero",
        "07-base-revision-zero.http",
        &serialize_request(&revision),
        "must conflict unless revision zero is currently valid",
    )?;

    let mut body_flip = parsed.clone();
    if body_flip.body.is_empty() {
        body_flip.body.push(0);
    } else {
        body_flip.body[0] ^= 0x01;
    }
    refresh_content_length(&mut body_flip);
    write_mutation(
        output_dir,
        cases,
        "body-bitflip",
        "08-body-bitflip.http",
        &serialize_request(&body_flip),
        "must fail signed-body binding or encrypted payload validation downstream",
    )?;

    let mut truncated = parsed.clone();
    truncated.body.truncate(truncated.body.len() / 2);
    refresh_content_length(&mut truncated);
    write_mutation(
        output_dir,
        cases,
        "body-truncate",
        "09-body-truncate.http",
        &serialize_request(&truncated),
        "must not be accepted as the original signed request",
    )
}

fn write_enrollment_recovery_mutations(
    output_dir: &Path,
    parsed: &ParsedRequest,
    cases: &mut Vec<RequestMutationCase>,
) -> Result<(), SyncApiError> {
    let enrollment_body = concat!(
        r#"{"deviceId":"00000000-0000-0000-0000-000000000001","#,
        r#""name":"","verifyingKeyHex":"00","proofSignatureHex":"00"}"#
    );
    let enrollment =
        synthesize_json_mutation(parsed, "/v1/devices/enroll", enrollment_body.as_bytes());
    write_mutation(
        output_dir,
        cases,
        "enrollment-invalid-proof",
        "10-enrollment-invalid-proof.http",
        &enrollment,
        "must reject invalid enrollment proof or invalid device key",
    )?;

    let recovery_body = concat!(
        r#"{"accountId":"00000000-0000-0000-0000-000000000001","#,
        r#""vaultId":"00000000-0000-0000-0000-000000000002","generation":1,"#,
        r#""timestamp":1,"nonceHex":"00","signatureHex":"00"}"#
    );
    let recovery = synthesize_json_mutation(
        parsed,
        "/v1/recovery/begin",
        recovery_body.as_bytes(),
    );
    write_mutation(
        output_dir,
        cases,
        "recovery-invalid-or-replayed-nonce",
        "11-recovery-invalid-or-replayed-nonce.http",
        &recovery,
        "must reject malformed, stale, invalid-signature, or replayed recovery authorization",
    )?;

    let malformed = concat!(
        "POST /v1/recovery/complete HTTP/1.1\r\n",
        "Host: 127.0.0.1\r\n",
        "Content-Type: application/json\r\n",
        "Content-Length: 1\r\n\r\n{"
    );
    write_mutation(
        output_dir,
        cases,
        "recovery-malformed-json",
        "12-recovery-malformed-json.http",
        malformed.as_bytes(),
        "must reject malformed recovery completion requests",
    )
}

fn parse_loopback_base_url(base_url: &str) -> Result<SocketAddrV4, SyncApiError> {
    let value = base_url
        .strip_prefix("http://")
        .ok_or(SyncApiError::InvalidBaseUrl)?;
    if value.contains('/') {
        return Err(SyncApiError::InvalidBaseUrl);
    }
    let (host, port) = value
        .rsplit_once(':')
        .ok_or(SyncApiError::InvalidBaseUrl)?;
    if host != "127.0.0.1" {
        return Err(SyncApiError::NonLoopbackTarget);
    }
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or(SyncApiError::InvalidBaseUrl)?;
    Ok(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
}


fn probe(
    endpoint: SocketAddrV4,
    id: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    expected_statuses: &[u16],
) -> Result<LiveProbeCase, SyncApiError> {
    let response = send_http(endpoint, method, path, headers, body)?;
    let passed = expected_statuses.contains(&response.0);
    Ok(LiveProbeCase {
        id: id.to_owned(),
        expected: expected_statuses
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join("|"),
        status: Some(response.0),
        passed,
        detail: if passed {
            "response matched the expected bounded security behavior".to_owned()
        } else {
            "response did not match the expected bounded security behavior".to_owned()
        },
    })
}

fn probe_health(endpoint: SocketAddrV4) -> Result<LiveProbeCase, SyncApiError> {
    let response = send_http(endpoint, "GET", "/v1/health", &[], &[])?;
    let passed = response.0 == 200 && check_security_headers(response.0, &response.1, &response.2);
    Ok(LiveProbeCase {
        id: "health".to_owned(),
        expected: "200 + security headers".to_owned(),
        status: Some(response.0),
        passed,
        detail: if passed {
            "health and response security headers matched expectations".to_owned()
        } else {
            "health or response security headers did not match expectations".to_owned()
        },
    })
}


fn probe_declared_oversize(
    endpoint: SocketAddrV4,
    id: &str,
    path: &str,
) -> Result<LiveProbeCase, SyncApiError> {
    let mut stream = TcpStream::connect_timeout(&endpoint.into(), CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    let request = format!(
        concat!(
            "POST {} HTTP/1.1\r\n",
            "Host: 127.0.0.1:{}\r\n",
            "Connection: close\r\n",
            "Content-Type: application/json\r\n",
            "Content-Length: {}\r\n\r\n"
        ),
        path,
        endpoint.port(),
        SYNC_REQUEST_LIMIT_BYTES + 1
    );
    stream.write_all(request.as_bytes())?;
    stream.shutdown(std::net::Shutdown::Write)?;

    let mut bytes = Vec::new();
    stream.take(128 * 1024).read_to_end(&mut bytes)?;
    let response = parse_http_response(&bytes)?;
    let passed = response.0 == 413;

    Ok(LiveProbeCase {
        id: id.to_owned(),
        expected: "413".to_owned(),
        status: Some(response.0),
        passed,
        detail: if passed {
            "declared request above the server body limit was rejected".to_owned()
        } else {
            "declared request above the server body limit was not rejected as expected".to_owned()
        },
    })
}

fn send_http(
    endpoint: SocketAddrV4,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<HttpResponse, SyncApiError> {
    let mut stream = TcpStream::connect_timeout(&endpoint.into(), CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    let mut request = format!(
        concat!(
            "{} {} HTTP/1.1\r\n",
            "Host: 127.0.0.1:{}\r\n",
            "Connection: close\r\n",
            "Content-Length: {}\r\n"
        ),
        method,
        path,
        endpoint.port(),
        body.len()
    );
    for (name, value) in headers {
        let _ = write!(request, "{name}: {value}\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes())?;
    stream.write_all(body)?;

    let mut bytes = Vec::new();
    stream.take(256 * 1024).read_to_end(&mut bytes)?;
    parse_http_response(&bytes)
}

fn parse_http_response(bytes: &[u8]) -> Result<HttpResponse, SyncApiError> {
    let split = find_bytes(bytes, b"\r\n\r\n").ok_or(SyncApiError::InvalidCapture)?;
    let head = std::str::from_utf8(&bytes[..split]).map_err(|_| SyncApiError::InvalidCapture)?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or(SyncApiError::InvalidCapture)?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or(SyncApiError::InvalidCapture)?;
    let headers = lines
        .filter_map(|line| {
            line.split_once(':')
                .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect();
    Ok((status, headers, bytes[split + 4..].to_vec()))
}

fn check_security_headers(status: u16, headers: &[(String, String)], _body: &[u8]) -> bool {
    status == 200
        && header_value(headers, "cache-control") == Some("no-store")
        && header_value(headers, "x-content-type-options") == Some("nosniff")
        && header_value(headers, "referrer-policy") == Some("no-referrer")
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<&str> {
    headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn parse_capture(bytes: &[u8]) -> Result<ParsedRequest, SyncApiError> {
    let split = find_bytes(bytes, b"\r\n\r\n").ok_or(SyncApiError::InvalidCapture)?;
    let head = std::str::from_utf8(&bytes[..split]).map_err(|_| SyncApiError::InvalidCapture)?;
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .filter(|line| line.split_whitespace().count() == 3)
        .ok_or(SyncApiError::InvalidCapture)?
        .to_owned();
    let headers = lines
        .map(|line| {
            line.split_once(':')
                .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
                .ok_or(SyncApiError::InvalidCapture)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ParsedRequest {
        request_line,
        headers,
        body: bytes[split + 4..].to_vec(),
    })
}

fn serialize_request(request: &ParsedRequest) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(request.request_line.as_bytes());
    output.extend_from_slice(b"\r\n");
    for (name, value) in &request.headers {
        output.extend_from_slice(name.as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(&request.body);
    output
}

fn remove_header(request: &mut ParsedRequest, name: &str) {
    request
        .headers
        .retain(|(header, _)| !header.eq_ignore_ascii_case(name));
}

fn set_header(request: &mut ParsedRequest, name: &str, value: &str) {
    if let Some((_, current)) = request
        .headers
        .iter_mut()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
    {
        *current = value.to_owned();
    } else {
        request.headers.push((name.to_owned(), value.to_owned()));
    }
}

fn refresh_content_length(request: &mut ParsedRequest) {
    set_header(request, "Content-Length", &request.body.len().to_string());
}

fn synthesize_json_mutation(parsed: &ParsedRequest, path: &str, body: &[u8]) -> Vec<u8> {
    let mut request = parsed.clone();
    request.request_line = format!("POST {path} HTTP/1.1");
    request.body = body.to_vec();
    set_header(&mut request, "Content-Type", "application/json");
    refresh_content_length(&mut request);
    serialize_request(&request)
}

fn write_mutation(
    output_dir: &Path,
    cases: &mut Vec<RequestMutationCase>,
    id: &str,
    filename: &str,
    bytes: &[u8],
    expected_behavior: &str,
) -> Result<(), SyncApiError> {
    fs::write(output_dir.join(filename), bytes)?;
    cases.push(RequestMutationCase {
        id: id.to_owned(),
        filename: filename.to_owned(),
        sha256: hex_digest(&sha256_bytes(bytes)),
        expected_behavior: expected_behavior.to_owned(),
    });
    Ok(())
}

fn write_manifest(output_dir: &Path) -> Result<(), SyncApiError> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(output_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "SHA256SUMS" {
                continue;
            }
            entries.push((name, fs::read(path)?));
        }
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let mut manifest = String::new();
    for (name, bytes) in entries {
        let _ = writeln!(
            manifest,
            "{}  {}",
            hex_digest(&sha256_bytes(&bytes)),
            name
        );
    }
    fs::write(output_dir.join("SHA256SUMS"), manifest)?;
    Ok(())
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
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
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpListener};
    use std::path::PathBuf;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        generate_sync_request_mutations, parse_capture, parse_loopback_base_url,
        run_sync_api_probe, SYNC_PROTOCOL_VERSION,
    };

    fn temp_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "dfstl-sync-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn protocol_baseline_is_v2() {
        assert_eq!(SYNC_PROTOCOL_VERSION, 2);
    }

    #[test]
    fn live_probe_refuses_non_loopback_targets() {
        assert!(parse_loopback_base_url("http://192.0.2.1:8787").is_err());
        assert!(parse_loopback_base_url("https://127.0.0.1:8787").is_err());
    }

    #[test]
    fn capture_parser_rejects_malformed_requests() {
        assert!(parse_capture(b"not-http").is_err());
    }

    #[test]
    fn loopback_probe_exercises_non_state_changing_matrix() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener");
        let port = listener.local_addr().expect("address").port();

        let handle = thread::spawn(move || {
            for _ in 0..8 {
                let (mut stream, _) = listener.accept().expect("accept");
                let mut bytes = Vec::new();
                let mut buffer = [0_u8; 4096];
                let header_end = loop {
                    let count = stream.read(&mut buffer).expect("read");
                    if count == 0 {
                        break None;
                    }
                    bytes.extend_from_slice(&buffer[..count]);
                    if let Some(index) = super::find_bytes(&bytes, b"\r\n\r\n") {
                        break Some(index);
                    }
                };
                let Some(header_end) = header_end else {
                    continue;
                };

                let head = String::from_utf8_lossy(&bytes[..header_end]);
                let request_line = head.lines().next().unwrap_or_default().to_owned();
                let content_length = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        if name.eq_ignore_ascii_case("content-length") {
                            value.trim().parse::<usize>().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);

                let body_start = header_end + 4;
                while bytes.len().saturating_sub(body_start) < content_length {
                    let count = stream.read(&mut buffer).expect("read body");
                    if count == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&buffer[..count]);
                }

                let status = if request_line.starts_with("GET /v1/health ") {
                    200
                } else if request_line.starts_with("GET /v1/devices ") {
                    401
                } else if request_line.starts_with("POST /v1/accounts ") {
                    403
                } else if request_line.starts_with("GET /v1/does-not-exist ") {
                    404
                } else if request_line.starts_with("POST /v1/health ") {
                    405
                } else if request_line.starts_with("POST /v1/recovery/begin ")
                    && content_length > super::SYNC_REQUEST_LIMIT_BYTES
                {
                    413
                } else {
                    422
                };

                let reason = match status {
                    200 => "OK",
                    401 => "Unauthorized",
                    403 => "Forbidden",
                    404 => "Not Found",
                    405 => "Method Not Allowed",
                    413 => "Content Too Large",
                    _ => "Unprocessable Entity",
                };
                let extra = if status == 200 {
                    concat!(
                        "Cache-Control: no-store\r\n",
                        "X-Content-Type-Options: nosniff\r\n",
                        "Referrer-Policy: no-referrer\r\n"
                    )
                } else {
                    ""
                };
                let response = format!(
                    concat!(
                        "HTTP/1.1 {} {}\r\n",
                        "{}Content-Length: 0\r\n",
                        "Connection: close\r\n\r\n"
                    ),
                    status,
                    reason,
                    extra
                );
                stream.write_all(response.as_bytes()).expect("response");
            }
        });

        let report = run_sync_api_probe(&format!("http://127.0.0.1:{port}")).expect("probe");
        assert!(report.all_expected());
        assert_eq!(report.cases.len(), 8);
        handle.join().expect("server");
    }

    #[test]
    fn offline_request_mutations_are_deterministic_and_non_destructive() {
        let capture = temp_path("capture.http");
        let output = temp_path("mutations");
        let source = concat!(
            "PUT /v1/vaults/00000000-0000-0000-0000-000000000001 HTTP/1.1\r\n",
            "Host: 127.0.0.1:8787\r\n",
            "Authorization: Bearer 1111111111111111111111111111111111111111111111111111111111111111\r\n",
            "X-DragonForge-Device-Id: 00000000-0000-0000-0000-000000000002\r\n",
            "X-DragonForge-Device-Timestamp: 1000\r\n",
            "X-DragonForge-Device-Signature: aabb\r\n",
            "X-DragonForge-Base-Revision: 7\r\n",
            "Content-Length: 4\r\n\r\n",
            "test"
        );
        fs::write(&capture, source).expect("capture");
        let before = fs::read(&capture).expect("before");
        let corpus = generate_sync_request_mutations(&capture, &output).expect("mutate");
        assert_eq!(corpus.cases.len(), 12);
        assert_eq!(fs::read(&capture).expect("after"), before);
        assert!(output.join("SHA256SUMS").is_file());
        fs::remove_file(capture).expect("cleanup capture");
        fs::remove_dir_all(output).expect("cleanup output");
    }
}
