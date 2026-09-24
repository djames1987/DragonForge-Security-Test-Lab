use std::fmt;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::hash::{hex_digest, sha256_bytes};

pub const MAX_ACL_RECORDS: usize = 256;
pub const MAX_ACL_PRINCIPAL_CHARS: usize = 256;
pub const MAX_ACL_PATH_CHARS: usize = 2048;

#[derive(Debug)]
pub enum AclLabError {
    Io(io::Error),
    InvalidRecord(String),
    TooManyRecords,
    OutputExists(PathBuf),
}

impl fmt::Display for AclLabError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => formatter.write_str("ACL lab I/O error"),
            Self::InvalidRecord(detail) => write!(formatter, "invalid ACL record: {detail}"),
            Self::TooManyRecords => formatter.write_str("too many ACL records"),
            Self::OutputExists(path) => {
                write!(formatter, "ACL evidence output already exists: {}", path.display())
            }
        }
    }
}

impl std::error::Error for AclLabError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for AclLabError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclRecord {
    pub target: String,
    pub owner: String,
    pub principal: String,
    pub access_type: String,
    pub rights: String,
    pub inherited: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclFinding {
    pub target: String,
    pub principal: String,
    pub severity: String,
    pub code: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclAnalysisReport {
    pub schema_version: u32,
    pub records: usize,
    pub findings: Vec<AclFinding>,
}

impl AclAnalysisReport {
    #[must_use]
    pub fn clean(&self) -> bool {
        self.findings.is_empty()
    }

    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(output, "{{");
        let _ = writeln!(output, "  \"schema_version\": {},", self.schema_version);
        let _ = writeln!(output, "  \"records\": {},", self.records);
        let _ = writeln!(output, "  \"clean\": {},", self.clean());
        let _ = writeln!(output, "  \"findings\": [");
        for (index, finding) in self.findings.iter().enumerate() {
            let comma = if index + 1 == self.findings.len() { "" } else { "," };
            let _ = writeln!(
                output,
                concat!(
                    "    {{\"target\":\"{}\",\"principal\":\"{}\",",
                    "\"severity\":\"{}\",\"code\":\"{}\",\"detail\":\"{}\"}}{}"
                ),
                json_escape(&finding.target),
                json_escape(&finding.principal),
                json_escape(&finding.severity),
                json_escape(&finding.code),
                json_escape(&finding.detail),
                comma
            );
        }
        let _ = writeln!(output, "  ]");
        let _ = writeln!(output, "}}");
        output
    }
}

/// Parses a bounded tab-separated ACL snapshot.
///
/// Expected columns:
/// target, owner, principal, access_type, rights, inherited
///
/// # Errors
///
/// Returns an error for malformed or oversized records.
pub fn parse_acl_snapshot(path: &Path) -> Result<Vec<AclRecord>, AclLabError> {
    let content = fs::read_to_string(path)?;
    let mut records = Vec::new();
    for (index, line) in content.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        if records.len() >= MAX_ACL_RECORDS {
            return Err(AclLabError::TooManyRecords);
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 6 {
            return Err(AclLabError::InvalidRecord(format!(
                "line {} must contain six tab-separated fields",
                index + 1
            )));
        }
        if fields[0].chars().count() > MAX_ACL_PATH_CHARS
            || fields[1].chars().count() > MAX_ACL_PRINCIPAL_CHARS
            || fields[2].chars().count() > MAX_ACL_PRINCIPAL_CHARS
        {
            return Err(AclLabError::InvalidRecord(format!(
                "line {} exceeds ACL field limits",
                index + 1
            )));
        }
        let inherited = match fields[5] {
            "true" => true,
            "false" => false,
            _ => {
                return Err(AclLabError::InvalidRecord(format!(
                    "line {} has invalid inherited flag",
                    index + 1
                )));
            }
        };
        records.push(AclRecord {
            target: fields[0].to_owned(),
            owner: fields[1].to_owned(),
            principal: fields[2].to_owned(),
            access_type: fields[3].to_ascii_lowercase(),
            rights: fields[4].to_owned(),
            inherited,
        });
    }
    Ok(records)
}

/// Analyzes ACL records for broad write access and unexpected inheritance.
#[must_use]
pub fn analyze_acl_records(records: &[AclRecord]) -> AclAnalysisReport {
    let mut findings = Vec::new();
    for record in records {
        let principal = normalize_principal(&record.principal);
        let broad = matches!(
            principal.as_str(),
            "everyone"
                | "builtin\\users"
                | "users"
                | "authenticated users"
                | "nt authority\\authenticated users"
        );
        let allowed = record.access_type == "allow";
        let writable = rights_are_write_capable(&record.rights);

        if broad && allowed && writable {
            findings.push(AclFinding {
                target: record.target.clone(),
                principal: record.principal.clone(),
                severity: "high".to_owned(),
                code: "broad-write".to_owned(),
                detail: "broad principal has write-capable access".to_owned(),
            });
        }

        if record.inherited && broad && allowed && writable {
            findings.push(AclFinding {
                target: record.target.clone(),
                principal: record.principal.clone(),
                severity: "high".to_owned(),
                code: "inherited-broad-write".to_owned(),
                detail: "write-capable broad access was inherited".to_owned(),
            });
        }

        if is_sensitive_target(&record.target)
            && record.inherited
            && allowed
            && writable
            && !is_expected_sensitive_principal(&principal)
        {
            findings.push(AclFinding {
                target: record.target.clone(),
                principal: record.principal.clone(),
                severity: "medium".to_owned(),
                code: "sensitive-inherited-write".to_owned(),
                detail: "sensitive target inherited write access from an unexpected principal"
                    .to_owned(),
            });
        }
    }

    AclAnalysisReport {
        schema_version: 1,
        records: records.len(),
        findings,
    }
}

/// Writes ACL analysis evidence and a SHA-256 manifest.
///
/// # Errors
///
/// Returns an error if the output exists or cannot be written.
pub fn write_acl_bundle(output_dir: &Path, report: &AclAnalysisReport) -> Result<(), AclLabError> {
    if output_dir.exists() {
        return Err(AclLabError::OutputExists(output_dir.to_path_buf()));
    }
    fs::create_dir(output_dir)?;
    fs::write(output_dir.join("acl-analysis.json"), report.to_json_pretty())?;
    let bytes = fs::read(output_dir.join("acl-analysis.json"))?;
    fs::write(
        output_dir.join("SHA256SUMS"),
        format!(
            "{}  acl-analysis.json\n",
            hex_digest(&sha256_bytes(&bytes))
        ),
    )?;
    Ok(())
}

fn normalize_principal(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn rights_are_write_capable(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    [
        "fullcontrol",
        "modify",
        "write",
        "createfiles",
        "createdirectories",
        "delete",
        "changepermissions",
        "takeownership",
    ]
    .iter()
    .any(|right| lowered.contains(right))
}

fn is_sensitive_target(value: &str) -> bool {
    let lowered = value.replace('/', "\\").to_ascii_lowercase();
    lowered.ends_with("\\agent-session.key")
        || lowered.ends_with("\\agent-runtime.json")
        || lowered.ends_with("\\agent.lock")
        || lowered.contains("\\privileged-service\\")
        || lowered.ends_with("\\service-config.json")
        || lowered.ends_with("\\firewall-policy-v1.json")
}

fn is_expected_sensitive_principal(value: &str) -> bool {
    value == "nt authority\\system"
        || value == "builtin\\administrators"
        || value.starts_with("nt service\\dragonforgeprivilegedservice")
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

    use super::{analyze_acl_records, parse_acl_snapshot, write_acl_bundle};

    fn temp_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "dfstl-acl-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn broad_write_is_reported() {
        let input = temp_path("broad.tsv");
        fs::write(
            &input,
            "C:\\\\lab\\\\agent-session.key\tOWNER\tBUILTIN\\\\Users\tAllow\tRead,Write\ttrue\n",
        )
        .expect("write");
        let records = parse_acl_snapshot(&input).expect("parse");
        let report = analyze_acl_records(&records);
        assert!(!report.clean());
        assert!(report.findings.iter().any(|item| item.code == "broad-write"));
        fs::remove_file(input).expect("cleanup");
    }

    #[test]
    fn restricted_sensitive_acl_is_clean() {
        let input = temp_path("clean.tsv");
        fs::write(
            &input,
            concat!(
                "C:\\\\lab\\\\agent-session.key\tOWNER\tOWNER\tAllow\tFullControl\tfalse\n",
                "C:\\\\lab\\\\agent-session.key\tOWNER\tNT AUTHORITY\\\\SYSTEM\tAllow\tFullControl\tfalse\n"
            ),
        )
        .expect("write");
        let records = parse_acl_snapshot(&input).expect("parse");
        let report = analyze_acl_records(&records);
        assert!(report.clean());
        fs::remove_file(input).expect("cleanup");
    }

    #[test]
    fn evidence_manifest_is_written() {
        let input = temp_path("manifest.tsv");
        let output = temp_path("manifest-out");
        fs::write(
            &input,
            "C:\\\\lab\\\\agent-runtime.json\tOWNER\tOWNER\tAllow\tFullControl\tfalse\n",
        )
        .expect("write");
        let records = parse_acl_snapshot(&input).expect("parse");
        let report = analyze_acl_records(&records);
        write_acl_bundle(&output, &report).expect("bundle");
        assert!(output.join("SHA256SUMS").is_file());
        fs::remove_file(input).expect("cleanup input");
        fs::remove_dir_all(output).expect("cleanup output");
    }
}
