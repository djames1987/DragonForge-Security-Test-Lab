use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};

use crate::hash::{hex_digest, sha256_bytes, sha256_file};

const MAX_SCAN_FILES: usize = 25_000;
const MAX_TEXT_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TOOL_OUTPUT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug)]
pub enum StaticScanError {
    Io(io::Error),
    SourceNotFound(PathBuf),
    SourceNotDirectory(PathBuf),
    UnsafeOutputPath(PathBuf),
}

impl fmt::Display for StaticScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => f.write_str("static scan I/O failure"),
            Self::SourceNotFound(path) => {
                write!(f, "source root does not exist: {}", path.display())
            }
            Self::SourceNotDirectory(path) => {
                write!(f, "source root is not a directory: {}", path.display())
            }
            Self::UnsafeOutputPath(path) => {
                write!(f, "unsafe output path: {}", path.display())
            }
        }
    }
}

impl std::error::Error for StaticScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for StaticScanError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingSeverity {
    Info,
    Warning,
    High,
}

impl FindingSeverity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticFinding {
    pub id: String,
    pub severity: FindingSeverity,
    pub path: String,
    pub line: Option<usize>,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyRecord {
    pub name: String,
    pub version: String,
    pub source: Option<String>,
    pub checksum: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanCounts {
    pub files_scanned: usize,
    pub secret_findings: usize,
    pub supply_chain_findings: usize,
    pub high_findings: usize,
    pub warning_findings: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticScanReport {
    pub schema_version: u32,
    pub source_root: PathBuf,
    pub source_fingerprint: String,
    pub coverage_truncated: bool,
    pub counts: ScanCounts,
    pub findings: Vec<StaticFinding>,
    pub dependencies: Vec<DependencyRecord>,
}

impl StaticScanReport {
    #[must_use]
    pub fn has_high_findings(&self) -> bool {
        self.counts.high_findings > 0
    }

    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(output, "{{");
        let _ = writeln!(output, "  \"schema_version\": {},", self.schema_version);
        let _ = writeln!(
            output,
            "  \"source_root\": \"{}\",",
            json_escape(&self.source_root.to_string_lossy())
        );
        let _ = writeln!(
            output,
            "  \"source_fingerprint\": \"{}\",",
            self.source_fingerprint
        );
        let _ = writeln!(
            output,
            "  \"coverage_truncated\": {},",
            self.coverage_truncated
        );
        let _ = writeln!(output, "  \"counts\": {{");
        let _ = writeln!(
            output,
            "    \"files_scanned\": {},",
            self.counts.files_scanned
        );
        let _ = writeln!(
            output,
            "    \"secret_findings\": {},",
            self.counts.secret_findings
        );
        let _ = writeln!(
            output,
            "    \"supply_chain_findings\": {},",
            self.counts.supply_chain_findings
        );
        let _ = writeln!(
            output,
            "    \"high_findings\": {},",
            self.counts.high_findings
        );
        let _ = writeln!(
            output,
            "    \"warning_findings\": {}",
            self.counts.warning_findings
        );
        let _ = writeln!(output, "  }},");
        let _ = writeln!(output, "  \"dependency_count\": {},", self.dependencies.len());
        let _ = writeln!(output, "  \"findings\": [");
        for (index, finding) in self.findings.iter().enumerate() {
            let comma = trailing_comma(index, self.findings.len());
            let line = finding
                .line
                .map_or_else(|| "null".to_owned(), |value| value.to_string());
            let _ = writeln!(output, "    {{");
            let _ = writeln!(output, "      \"id\": \"{}\",", json_escape(&finding.id));
            let _ = writeln!(
                output,
                "      \"severity\": \"{}\",",
                finding.severity.as_str()
            );
            let _ = writeln!(
                output,
                "      \"path\": \"{}\",",
                json_escape(&finding.path)
            );
            let _ = writeln!(output, "      \"line\": {line},");
            let _ = writeln!(
                output,
                "      \"summary\": \"{}\"",
                json_escape(&finding.summary)
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
        let _ = writeln!(output, "DragonForge static security scan");
        let _ = writeln!(output, "Source: {}", self.source_root.display());
        let _ = writeln!(output, "Fingerprint: {}", self.source_fingerprint);
        let _ = writeln!(output, "Coverage truncated: {}", self.coverage_truncated);
        let _ = writeln!(output, "Files discovered: {}", self.counts.files_scanned);
        let _ = writeln!(output, "Dependencies: {}", self.dependencies.len());
        let _ = writeln!(output, "Secret findings: {}", self.counts.secret_findings);
        let _ = writeln!(
            output,
            "Supply-chain findings: {}",
            self.counts.supply_chain_findings
        );
        let _ = writeln!(output, "High findings: {}", self.counts.high_findings);
        let _ = writeln!(output, "Warnings: {}", self.counts.warning_findings);
        for finding in &self.findings {
            let location = finding.line.map_or_else(
                || finding.path.clone(),
                |line| format!("{}:{line}", finding.path),
            );
            let _ = writeln!(
                output,
                "{} {} {} - {}",
                finding.severity.as_str(),
                finding.id,
                location,
                finding.summary
            );
        }
        output
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalToolStatus {
    Passed,
    Failed(i32),
    Unavailable,
}

impl ExternalToolStatus {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed(_) => "failed",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalToolResult {
    pub tool: String,
    pub status: ExternalToolStatus,
    pub output: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalScanResults {
    pub cargo_audit: ExternalToolResult,
    pub cargo_deny: ExternalToolResult,
    pub gitleaks_history: ExternalToolResult,
}

impl ExternalScanResults {
    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(output, "{{");
        write_tool_json(&mut output, "cargo_audit", &self.cargo_audit, true);
        write_tool_json(&mut output, "cargo_deny", &self.cargo_deny, true);
        write_tool_json(
            &mut output,
            "gitleaks_history",
            &self.gitleaks_history,
            false,
        );
        let _ = writeln!(output, "}}");
        output
    }
}

/// Performs bounded, read-only source scanning.
///
/// # Errors
///
/// Returns an error when the source root is invalid or repository files cannot
/// be enumerated/read.
pub fn scan_source(root: &Path) -> Result<StaticScanReport, StaticScanError> {
    validate_source(root)?;

    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    files.sort();
    let coverage_truncated = files.len() >= MAX_SCAN_FILES;

    let mut findings = Vec::new();
    let mut fingerprint_material = Vec::new();

    for relative in &files {
        let full = root.join(relative);
        let metadata = fs::symlink_metadata(&full)?;
        if metadata.len() > MAX_TEXT_FILE_BYTES {
            continue;
        }
        let Ok(bytes) = fs::read(&full) else {
            continue;
        };
        let digest = hex_digest(&sha256_bytes(&bytes));
        fingerprint_material.extend_from_slice(relative.to_string_lossy().as_bytes());
        fingerprint_material.push(0);
        fingerprint_material.extend_from_slice(digest.as_bytes());
        fingerprint_material.push(b'\n');

        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        scan_secrets(relative, &text, &mut findings);
        if is_workflow(relative) {
            scan_workflow(relative, &text, &mut findings);
        }
    }

    let dependencies = parse_cargo_lock(root)?;
    let source_fingerprint = hex_digest(&sha256_bytes(&fingerprint_material));
    findings.sort_by(|left, right| {
        (&left.path, left.line, &left.id).cmp(&(&right.path, right.line, &right.id))
    });

    let mut counts = ScanCounts {
        files_scanned: files.len(),
        ..ScanCounts::default()
    };
    for finding in &findings {
        if finding.id.starts_with("SECRET-") {
            counts.secret_findings += 1;
        } else {
            counts.supply_chain_findings += 1;
        }
        match finding.severity {
            FindingSeverity::High => counts.high_findings += 1,
            FindingSeverity::Warning => counts.warning_findings += 1,
            FindingSeverity::Info => {}
        }
    }

    Ok(StaticScanReport {
        schema_version: 1,
        source_root: root.to_path_buf(),
        source_fingerprint,
        coverage_truncated,
        counts,
        findings,
        dependencies,
    })
}

/// Writes the built-in scan report, dependency inventory, and SPDX 2.3 SBOM.
///
/// # Errors
///
/// Returns an error for unsafe output paths or failed writes.
pub fn write_scan_bundle(
    output_root: &Path,
    report: &StaticScanReport,
) -> Result<(), StaticScanError> {
    validate_output_path(output_root)?;
    fs::create_dir_all(output_root)?;
    fs::write(output_root.join("static-scan.json"), report.to_json_pretty())?;
    fs::write(output_root.join("static-scan.txt"), report.to_text())?;
    fs::write(
        output_root.join("dependency-inventory.json"),
        dependency_inventory_json(&report.dependencies),
    )?;
    fs::write(
        output_root.join("sbom.spdx.json"),
        spdx_json(&report.dependencies, &report.source_fingerprint),
    )?;
    Ok(())
}

/// Runs optional read-only external scanners. Missing tools are reported as
/// unavailable rather than as a clean pass.
///
/// # Errors
///
/// Returns an error only when the output directory cannot be prepared/written.
pub fn run_external_scanners(
    source_root: &Path,
    output_root: &Path,
) -> Result<ExternalScanResults, StaticScanError> {
    validate_source(source_root)?;
    validate_output_path(output_root)?;
    fs::create_dir_all(output_root)?;

    let cargo_audit = run_tool(
        "cargo-audit",
        Command::new("cargo")
            .current_dir(source_root)
            .args(["audit", "--json"]),
    );
    let cargo_deny = run_tool(
        "cargo-deny",
        Command::new("cargo")
            .current_dir(source_root)
            .args(["deny", "check"]),
    );

    let gitleaks_report = output_root.join("gitleaks-history.json");
    let gitleaks = run_tool(
        "gitleaks",
        Command::new("gitleaks")
            .current_dir(source_root)
            .args(["git", "--redact", "--report-format", "json", "--report-path"])
            .arg(&gitleaks_report),
    );

    let results = ExternalScanResults {
        cargo_audit,
        cargo_deny,
        gitleaks_history: gitleaks,
    };
    fs::write(
        output_root.join("external-tools.json"),
        results.to_json_pretty(),
    )?;
    Ok(results)
}

#[must_use]
pub fn dependency_inventory_json(dependencies: &[DependencyRecord]) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "{{");
    let _ = writeln!(output, "  \"schema_version\": 1,");
    let _ = writeln!(output, "  \"dependencies\": [");
    for (index, dependency) in dependencies.iter().enumerate() {
        let comma = trailing_comma(index, dependencies.len());
        let _ = writeln!(output, "    {{");
        let _ = writeln!(
            output,
            "      \"name\": \"{}\",",
            json_escape(&dependency.name)
        );
        let _ = writeln!(
            output,
            "      \"version\": \"{}\",",
            json_escape(&dependency.version)
        );
        write_optional_json(
            &mut output,
            "source",
            dependency.source.as_deref(),
            true,
            6,
        );
        write_optional_json(
            &mut output,
            "checksum",
            dependency.checksum.as_deref(),
            false,
            6,
        );
        let _ = writeln!(output, "    }}{comma}");
    }
    let _ = writeln!(output, "  ]");
    let _ = writeln!(output, "}}");
    output
}

#[must_use]
pub fn spdx_json(dependencies: &[DependencyRecord], source_fingerprint: &str) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "{{");
    let _ = writeln!(output, "  \"spdxVersion\": \"SPDX-2.3\",");
    let _ = writeln!(output, "  \"dataLicense\": \"CC0-1.0\",");
    let _ = writeln!(output, "  \"SPDXID\": \"SPDXRef-DOCUMENT\",");
    let _ = writeln!(output, "  \"name\": \"DFSTL Cargo dependency SBOM\",");
    let _ = writeln!(
        output,
        "  \"documentNamespace\": \"urn:dfstl:spdx:{}\",",
        source_fingerprint
    );
    let _ = writeln!(
        output,
        concat!(
            "  \"creationInfo\": {{\"creators\": ",
            "[\"Tool: DragonForge-Security-Test-Lab\"], ",
            "\"created\": \"1970-01-01T00:00:00Z\"}},"
        )
    );
    let _ = writeln!(output, "  \"packages\": [");
    for (index, dependency) in dependencies.iter().enumerate() {
        let comma = trailing_comma(index, dependencies.len());
        let spdx_id = format!("SPDXRef-Package-{index}");
        let download = dependency.source.as_deref().unwrap_or("NOASSERTION");
        let _ = writeln!(output, "    {{");
        let _ = writeln!(output, "      \"SPDXID\": \"{spdx_id}\",");
        let _ = writeln!(
            output,
            "      \"name\": \"{}\",",
            json_escape(&dependency.name)
        );
        let _ = writeln!(
            output,
            "      \"versionInfo\": \"{}\",",
            json_escape(&dependency.version)
        );
        let _ = writeln!(
            output,
            "      \"downloadLocation\": \"{}\",",
            json_escape(download)
        );
        let _ = writeln!(output, "      \"filesAnalyzed\": false,");
        let _ = writeln!(output, "      \"licenseConcluded\": \"NOASSERTION\",");
        let _ = writeln!(output, "      \"licenseDeclared\": \"NOASSERTION\"");
        let _ = writeln!(output, "    }}{comma}");
    }
    let _ = writeln!(output, "  ]");
    let _ = writeln!(output, "}}");
    output
}

fn validate_source(root: &Path) -> Result<(), StaticScanError> {
    if !root.exists() {
        return Err(StaticScanError::SourceNotFound(root.to_path_buf()));
    }
    if !root.is_dir() {
        return Err(StaticScanError::SourceNotDirectory(root.to_path_buf()));
    }
    Ok(())
}

fn validate_output_path(path: &Path) -> Result<(), StaticScanError> {
    if path.as_os_str().is_empty() {
        return Err(StaticScanError::UnsafeOutputPath(path.to_path_buf()));
    }
    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(StaticScanError::UnsafeOutputPath(path.to_path_buf()));
        }
    }
    Ok(())
}

fn collect_files(
    root: &Path,
    current: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), StaticScanError> {
    if files.len() >= MAX_SCAN_FILES {
        return Ok(());
    }

    for entry in fs::read_dir(current)? {
        if files.len() >= MAX_SCAN_FILES {
            break;
        }
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if matches!(
                name.as_ref(),
                ".git" | "target" | "node_modules" | "dist" | "test-logs" | "results"
            ) {
                continue;
            }
            collect_files(root, &path, files)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| StaticScanError::UnsafeOutputPath(path.clone()))?;
            files.push(relative.to_path_buf());
        }
    }
    Ok(())
}

fn scan_secrets(path: &Path, text: &str, findings: &mut Vec<StaticFinding>) {
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        let patterns = [
            ("SECRET-PRIVATE-KEY", "-----BEGIN PRIVATE KEY-----"),
            ("SECRET-GITHUB-PAT", "github_pat_"),
            ("SECRET-GITHUB-TOKEN", "ghp_"),
        ];
        for (id, pattern) in patterns {
            if line.contains(pattern) {
                findings.push(StaticFinding {
                    id: id.to_owned(),
                    severity: FindingSeverity::High,
                    path: normalized_path(path),
                    line: Some(line_number),
                    summary: format!("possible committed secret matching {id}"),
                });
            }
        }

        if contains_aws_access_key(line) {
            findings.push(StaticFinding {
                id: "SECRET-AWS-ACCESS-KEY".to_owned(),
                severity: FindingSeverity::High,
                path: normalized_path(path),
                line: Some(line_number),
                summary: "possible AWS access key identifier".to_owned(),
            });
        }
    }
}

fn scan_workflow(path: &Path, text: &str, findings: &mut Vec<StaticFinding>) {
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        let line_number = index + 1;

        if let Some(action) = trimmed
            .strip_prefix("- uses:")
            .or_else(|| trimmed.strip_prefix("uses:"))
        {
            let action = action.trim();
            if action.starts_with("./") {
                continue;
            }
            let pinned = action
                .rsplit_once('@')
                .is_some_and(|(_, reference)| is_full_git_sha(reference));
            if !pinned {
                findings.push(StaticFinding {
                    id: "SUPPLY-ACTION-UNPINNED".to_owned(),
                    severity: FindingSeverity::Warning,
                    path: normalized_path(path),
                    line: Some(line_number),
                    summary: format!("GitHub Action is not pinned to a full commit SHA: {action}"),
                });
            }
        }

        if trimmed == "runs-on: self-hosted" || trimmed.contains("[self-hosted") {
            findings.push(StaticFinding {
                id: "SUPPLY-SELF-HOSTED-RUNNER".to_owned(),
                severity: FindingSeverity::Warning,
                path: normalized_path(path),
                line: Some(line_number),
                summary: concat!(
                    "workflow uses a self-hosted runner; ",
                    "persistent-runner trust must be reviewed"
                )
                .to_owned(),
            });
        }

        if trimmed == "permissions: write-all" {
            findings.push(StaticFinding {
                id: "SUPPLY-WRITE-ALL".to_owned(),
                severity: FindingSeverity::High,
                path: normalized_path(path),
                line: Some(line_number),
                summary: "workflow grants write-all token permissions".to_owned(),
            });
        }

        if trimmed == "pull_request_target:" {
            findings.push(StaticFinding {
                id: "SUPPLY-PR-TARGET".to_owned(),
                severity: FindingSeverity::Warning,
                path: normalized_path(path),
                line: Some(line_number),
                summary: "pull_request_target requires careful untrusted-code review".to_owned(),
            });
        }
    }
}

fn parse_cargo_lock(root: &Path) -> Result<Vec<DependencyRecord>, StaticScanError> {
    let path = root.join("Cargo.lock");
    if !path.is_file() {
        return Ok(Vec::new());
    }

    let text = fs::read_to_string(path)?;
    let mut dependencies = Vec::new();
    let mut current: BTreeMap<String, String> = BTreeMap::new();

    for line in text.lines().chain(std::iter::once("[[package]]")) {
        if line.trim() == "[[package]]" {
            if let (Some(name), Some(version)) =
                (current.remove("name"), current.remove("version"))
            {
                dependencies.push(DependencyRecord {
                    name,
                    version,
                    source: current.remove("source"),
                    checksum: current.remove("checksum"),
                });
            }
            current.clear();
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if matches!(key, "name" | "version" | "source" | "checksum") {
            current.insert(key.to_owned(), unquote(value.trim()));
        }
    }

    dependencies.sort_by(|left, right| {
        (&left.name, &left.version, &left.source).cmp(&(&right.name, &right.version, &right.source))
    });
    Ok(dependencies)
}

fn contains_aws_access_key(line: &str) -> bool {
    let bytes = line.as_bytes();
    for window in bytes.windows(20) {
        if window.starts_with(b"AKIA")
            && window[4..]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        {
            return true;
        }
    }
    false
}

fn is_workflow(path: &Path) -> bool {
    let normalized = normalized_path(path).to_ascii_lowercase();
    normalized.starts_with(".github/workflows/")
        && Path::new(&normalized)
            .extension()
            .is_some_and(|extension| {
                extension.eq_ignore_ascii_case("yml") || extension.eq_ignore_ascii_case("yaml")
            })
}

fn is_full_git_sha(reference: &str) -> bool {
    reference.len() == 40 && reference.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn unquote(value: &str) -> String {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value)
        .to_owned()
}

fn normalized_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn trailing_comma(index: usize, len: usize) -> &'static str {
    if index + 1 == len { "" } else { "," }
}

fn write_optional_json(
    output: &mut String,
    key: &str,
    value: Option<&str>,
    comma: bool,
    indent: usize,
) {
    let prefix = " ".repeat(indent);
    let suffix = if comma { "," } else { "" };
    match value {
        Some(value) => {
            let _ = writeln!(
                output,
                "{prefix}\"{}\": \"{}\"{suffix}",
                json_escape(key),
                json_escape(value)
            );
        }
        None => {
            let _ = writeln!(output, "{prefix}\"{}\": null{suffix}", json_escape(key));
        }
    }
}

fn write_tool_json(output: &mut String, key: &str, result: &ExternalToolResult, comma: bool) {
    let suffix = if comma { "," } else { "" };
    let exit_code = match result.status {
        ExternalToolStatus::Failed(code) => code.to_string(),
        ExternalToolStatus::Passed | ExternalToolStatus::Unavailable => "null".to_owned(),
    };
    let _ = writeln!(output, "  \"{}\": {{", json_escape(key));
    let _ = writeln!(
        output,
        "    \"tool\": \"{}\",",
        json_escape(&result.tool)
    );
    let _ = writeln!(
        output,
        "    \"status\": \"{}\",",
        result.status.as_str()
    );
    let _ = writeln!(output, "    \"exit_code\": {exit_code},");
    let _ = writeln!(
        output,
        "    \"output\": \"{}\"",
        json_escape(&result.output)
    );
    let _ = writeln!(output, "  }}{suffix}");
}

fn run_tool(tool: &str, command: &mut Command) -> ExternalToolResult {
    match command.output() {
        Ok(output) => tool_result(tool, output),
        Err(error) if error.kind() == io::ErrorKind::NotFound => ExternalToolResult {
            tool: tool.to_owned(),
            status: ExternalToolStatus::Unavailable,
            output: "tool not installed or command unavailable".to_owned(),
        },
        Err(error) => ExternalToolResult {
            tool: tool.to_owned(),
            status: ExternalToolStatus::Failed(-1),
            output: error.to_string(),
        },
    }
}

fn tool_result(tool: &str, output: Output) -> ExternalToolResult {
    let code = output.status.code().unwrap_or(-1);
    let status = if output.status.success() {
        ExternalToolStatus::Passed
    } else if looks_like_missing_cargo_subcommand(&output) {
        ExternalToolStatus::Unavailable
    } else {
        ExternalToolStatus::Failed(code)
    };
    let mut combined = output.stdout;
    combined.extend_from_slice(&output.stderr);
    if combined.len() > MAX_TOOL_OUTPUT_BYTES {
        combined.truncate(MAX_TOOL_OUTPUT_BYTES);
    }
    ExternalToolResult {
        tool: tool.to_owned(),
        status,
        output: String::from_utf8_lossy(&combined).into_owned(),
    }
}

fn looks_like_missing_cargo_subcommand(output: &Output) -> bool {
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    stderr.contains("no such command") || stderr.contains("no such subcommand")
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
        ExternalToolStatus, FindingSeverity, dependency_inventory_json, scan_source, spdx_json,
        write_scan_bundle,
    };

    fn temp_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "dfstl-static-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn write_fixture(root: &Path) {
        fs::create_dir_all(root.join(".github/workflows")).expect("workflow dir");
        fs::write(
            root.join("Cargo.lock"),
            concat!(
                "# synthetic\nversion = 4\n\n",
                "[[package]]\nname = \"alpha\"\nversion = \"1.2.3\"\n",
                "source = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
                "checksum = \"abc\"\n\n",
                "[[package]]\nname = \"workspace-app\"\nversion = \"0.1.0\"\n",
            ),
        )
        .expect("lock");
        fs::write(
            root.join(".github/workflows/ci.yml"),
            concat!(
                "permissions:\n  contents: read\n",
                "jobs:\n  test:\n    runs-on: self-hosted\n    steps:\n",
                "      - uses: actions/checkout@v4\n",
            ),
        )
        .expect("workflow");
        fs::write(
            root.join("config.txt"),
            "fixture = github_pat_SYNTHETIC_NOT_REAL_12345678901234567890\n",
        )
        .expect("secret fixture");
    }

    #[test]
    fn scan_finds_synthetic_secret_and_supply_chain_findings() {
        let root = temp_root("scan");
        write_fixture(&root);

        let report = scan_source(&root).expect("scan");
        assert_eq!(report.dependencies.len(), 2);
        assert_eq!(report.counts.secret_findings, 1);
        assert_eq!(report.counts.high_findings, 1);
        assert_eq!(report.counts.supply_chain_findings, 2);
        assert!(report.has_high_findings());
        assert!(report.findings.iter().any(|finding| {
            finding.id == "SECRET-GITHUB-PAT" && finding.severity == FindingSeverity::High
        }));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.id == "SUPPLY-ACTION-UNPINNED"));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.id == "SUPPLY-SELF-HOSTED-RUNNER"));

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn full_sha_action_is_not_reported_unpinned() {
        let root = temp_root("pinned");
        fs::create_dir_all(root.join(".github/workflows")).expect("workflow dir");
        fs::write(
            root.join(".github/workflows/ci.yml"),
            "steps:\n  - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n",
        )
        .expect("workflow");

        let report = scan_source(&root).expect("scan");
        assert!(!report
            .findings
            .iter()
            .any(|finding| finding.id == "SUPPLY-ACTION-UNPINNED"));

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn inventory_and_spdx_are_machine_readable_shapes() {
        let root = temp_root("sbom");
        write_fixture(&root);
        let report = scan_source(&root).expect("scan");

        let inventory = dependency_inventory_json(&report.dependencies);
        assert!(inventory.contains("\"schema_version\": 1"));
        assert!(inventory.contains("\"name\": \"alpha\""));

        let spdx = spdx_json(&report.dependencies, &report.source_fingerprint);
        assert!(spdx.contains("\"spdxVersion\": \"SPDX-2.3\""));
        assert!(spdx.contains("\"SPDXID\": \"SPDXRef-DOCUMENT\""));

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn scan_bundle_contains_required_artifacts() {
        let root = temp_root("bundle-source");
        let output = temp_root("bundle-output");
        write_fixture(&root);
        let report = scan_source(&root).expect("scan");
        write_scan_bundle(&output, &report).expect("bundle");

        for name in [
            "static-scan.json",
            "static-scan.txt",
            "dependency-inventory.json",
            "sbom.spdx.json",
        ] {
            assert!(output.join(name).is_file(), "{name} missing");
        }

        fs::remove_dir_all(root).expect("cleanup source");
        fs::remove_dir_all(output).expect("cleanup output");
    }

    #[test]
    fn unavailable_status_is_distinct_from_pass() {
        assert_ne!(ExternalToolStatus::Unavailable, ExternalToolStatus::Passed);
    }
}
