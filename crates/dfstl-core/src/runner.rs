use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::evidence::{EvidenceError, EvidenceLimits, EvidenceSession};
use crate::model::{ExecutionPolicy, TestDescriptor, TestStatus};

static RUN_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub relative_path: String,
    pub bytes: Vec<u8>,
}

impl Artifact {
    #[must_use]
    pub fn new(relative_path: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            relative_path: relative_path.into(),
            bytes: bytes.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestExecution {
    pub status: TestStatus,
    pub summary: String,
    pub artifacts: Vec<Artifact>,
}

impl TestExecution {
    #[must_use]
    pub fn new(status: TestStatus, summary: impl Into<String>) -> Self {
        Self {
            status,
            summary: summary.into(),
            artifacts: Vec::new(),
        }
    }

    #[must_use]
    pub fn pass(summary: impl Into<String>) -> Self {
        Self::new(TestStatus::Pass, summary)
    }

    #[must_use]
    pub fn with_artifact(mut self, artifact: Artifact) -> Self {
        self.artifacts.push(artifact);
        self
    }
}

pub struct TestContext<'a> {
    pub run_id: &'a str,
    pub policy: ExecutionPolicy,
}

pub trait SecurityTest {
    fn descriptor(&self) -> &TestDescriptor;

    /// Executes one test inside the centrally authorized run context.
    ///
    /// # Errors
    ///
    /// Returns an infrastructure-oriented error string when the test itself
    /// cannot reliably execute. Target security failures belong in a
    /// successful TestExecution with TestStatus::Fail.
    fn execute(&self, context: &TestContext<'_>) -> Result<TestExecution, String>;
}

#[derive(Default)]
pub struct TestRegistry {
    tests: Vec<Box<dyn SecurityTest>>,
    ids: BTreeSet<&'static str>,
}

impl TestRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a test and rejects duplicate or malformed stable IDs.
    ///
    /// # Errors
    ///
    /// Returns a string describing an invalid or duplicate test identifier.
    pub fn register<T: SecurityTest + 'static>(&mut self, test: T) -> Result<(), String> {
        let id = test.descriptor().id;
        validate_test_id(id)?;
        if !self.ids.insert(id) {
            return Err(format!("duplicate test id: {id}"));
        }
        self.tests.push(Box::new(test));
        Ok(())
    }

    #[must_use]
    pub fn iter(&self) -> impl Iterator<Item = &dyn SecurityTest> {
        self.tests.iter().map(Box::as_ref)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.tests.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tests.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestRecord {
    pub id: String,
    pub name: String,
    pub category: String,
    pub safety: String,
    pub model: String,
    pub status: TestStatus,
    pub summary: String,
    pub duration_ms: u128,
    pub artifact_count: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunCounts {
    pub pass: usize,
    pub fail: usize,
    pub warning: usize,
    pub skipped: usize,
    pub infrastructure_error: usize,
}

impl RunCounts {
    fn record(&mut self, status: TestStatus) {
        match status {
            TestStatus::Pass => self.pass += 1,
            TestStatus::Fail => self.fail += 1,
            TestStatus::Warning => self.warning += 1,
            TestStatus::Skipped => self.skipped += 1,
            TestStatus::InfrastructureError => self.infrastructure_error += 1,
        }
    }

    #[must_use]
    pub const fn has_failures(self) -> bool {
        self.fail > 0 || self.infrastructure_error > 0
    }

    #[must_use]
    pub const fn total(self) -> usize {
        self.pass + self.fail + self.warning + self.skipped + self.infrastructure_error
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReport {
    pub schema_version: u32,
    pub run_id: String,
    pub started_unix_ms: u128,
    pub finished_unix_ms: u128,
    pub maximum_safety_class: String,
    pub counts: RunCounts,
    pub tests: Vec<TestRecord>,
}

impl RunReport {
    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(output, "{{");
        let _ = writeln!(output, "  \"schema_version\": {},", self.schema_version);
        let _ = writeln!(output, "  \"run_id\": \"{}\",", json_escape(&self.run_id));
        let _ = writeln!(output, "  \"started_unix_ms\": {},", self.started_unix_ms);
        let _ = writeln!(output, "  \"finished_unix_ms\": {},", self.finished_unix_ms);
        let _ = writeln!(
            output,
            "  \"maximum_safety_class\": \"{}\",",
            json_escape(&self.maximum_safety_class)
        );
        let _ = writeln!(output, "  \"counts\": {{");
        let _ = writeln!(output, "    \"pass\": {},", self.counts.pass);
        let _ = writeln!(output, "    \"fail\": {},", self.counts.fail);
        let _ = writeln!(output, "    \"warning\": {},", self.counts.warning);
        let _ = writeln!(output, "    \"skipped\": {},", self.counts.skipped);
        let _ = writeln!(
            output,
            "    \"infrastructure_error\": {}",
            self.counts.infrastructure_error
        );
        let _ = writeln!(output, "  }},");
        let _ = writeln!(output, "  \"tests\": [");
        for (index, test) in self.tests.iter().enumerate() {
            let comma = if index + 1 == self.tests.len() { "" } else { "," };
            let _ = writeln!(output, "    {{");
            let _ = writeln!(output, "      \"id\": \"{}\",", json_escape(&test.id));
            let _ = writeln!(output, "      \"name\": \"{}\",", json_escape(&test.name));
            let _ = writeln!(
                output,
                "      \"category\": \"{}\",",
                json_escape(&test.category)
            );
            let _ = writeln!(output, "      \"safety\": \"{}\",", json_escape(&test.safety));
            let _ = writeln!(output, "      \"model\": \"{}\",", json_escape(&test.model));
            let _ = writeln!(output, "      \"status\": \"{}\",", test.status.as_str());
            let _ = writeln!(
                output,
                "      \"summary\": \"{}\",",
                json_escape(&test.summary)
            );
            let _ = writeln!(output, "      \"duration_ms\": {},", test.duration_ms);
            let _ = writeln!(
                output,
                "      \"artifact_count\": {}",
                test.artifact_count
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
        let _ = writeln!(output, "DragonForge Security Test Lab");
        let _ = writeln!(output, "Run ID: {}", self.run_id);
        let _ = writeln!(output, "Safety policy: {}", self.maximum_safety_class);
        let _ = writeln!(output);
        for test in &self.tests {
            let _ = writeln!(
                output,
                "{:<21} {:<20} {}",
                test.id,
                test.status.as_str(),
                test.summary
            );
        }
        let _ = writeln!(output);
        let _ = writeln!(output, "Total: {}", self.counts.total());
        let _ = writeln!(output, "Passed: {}", self.counts.pass);
        let _ = writeln!(output, "Failed: {}", self.counts.fail);
        let _ = writeln!(output, "Warnings: {}", self.counts.warning);
        let _ = writeln!(output, "Skipped: {}", self.counts.skipped);
        let _ = writeln!(
            output,
            "Infrastructure errors: {}",
            self.counts.infrastructure_error
        );
        output
    }
}

pub struct CompletedRun {
    pub report: RunReport,
    pub evidence_dir: PathBuf,
}

pub struct Runner {
    policy: ExecutionPolicy,
    evidence_root: PathBuf,
    evidence_limits: EvidenceLimits,
}

impl Runner {
    #[must_use]
    pub fn new(policy: ExecutionPolicy, evidence_root: impl Into<PathBuf>) -> Self {
        Self {
            policy,
            evidence_root: evidence_root.into(),
            evidence_limits: EvidenceLimits::default(),
        }
    }

    #[must_use]
    pub const fn with_evidence_limits(mut self, limits: EvidenceLimits) -> Self {
        self.evidence_limits = limits;
        self
    }

    /// Executes all registered tests and finalizes a tamper-evident evidence bundle.
    ///
    /// # Errors
    ///
    /// Returns an evidence error if the run directory cannot be staged or
    /// finalized. Individual test execution errors are recorded as
    /// infrastructure-error results instead of aborting the run.
    pub fn run(&self, registry: &TestRegistry) -> Result<CompletedRun, EvidenceError> {
        let run_id = new_run_id();
        let started = unix_ms();
        let mut session =
            EvidenceSession::new(&self.evidence_root, &run_id, self.evidence_limits)?;
        let context = TestContext {
            run_id: &run_id,
            policy: self.policy,
        };
        let mut counts = RunCounts::default();
        let mut records = Vec::with_capacity(registry.len());

        for test in registry.iter() {
            let descriptor = test.descriptor();
            let test_started = std::time::Instant::now();
            let (mut status, mut summary, artifacts) = if !self.policy.allows(descriptor.safety) {
                (
                    TestStatus::Skipped,
                    format!(
                        "blocked by safety policy: {} exceeds {}",
                        descriptor.safety,
                        self.policy.maximum_class()
                    ),
                    Vec::new(),
                )
            } else {
                match test.execute(&context) {
                    Ok(execution) => (
                        execution.status,
                        execution.summary,
                        execution.artifacts,
                    ),
                    Err(error) => (
                        TestStatus::InfrastructureError,
                        format!("test execution error: {error}"),
                        Vec::new(),
                    ),
                }
            };

            let mut artifact_count = 0_usize;
            for artifact in artifacts {
                let artifact_path = Path::new("artifacts")
                    .join(descriptor.id)
                    .join(&artifact.relative_path);
                match session.write_artifact(&artifact_path, &artifact.bytes) {
                    Ok(()) => artifact_count += 1,
                    Err(error) => {
                        status = TestStatus::InfrastructureError;
                        summary = format!("evidence persistence failed: {error}");
                        break;
                    }
                }
            }

            counts.record(status);
            records.push(TestRecord {
                id: descriptor.id.to_owned(),
                name: descriptor.name.to_owned(),
                category: descriptor.category.code().to_owned(),
                safety: descriptor.safety.as_str().to_owned(),
                model: descriptor.model.as_str().to_owned(),
                status,
                summary,
                duration_ms: test_started.elapsed().as_millis(),
                artifact_count,
            });
        }

        let report = RunReport {
            schema_version: 1,
            run_id,
            started_unix_ms: started,
            finished_unix_ms: unix_ms(),
            maximum_safety_class: self.policy.maximum_class().as_str().to_owned(),
            counts,
            tests: records,
        };
        let evidence_dir = session.finalize(&report.to_json_pretty(), &report.to_text())?;

        Ok(CompletedRun {
            report,
            evidence_dir,
        })
    }
}

fn validate_test_id(id: &str) -> Result<(), String> {
    if id.len() < 5 || id.len() > 64 {
        return Err(format!("invalid test id length: {id}"));
    }
    if !id.bytes().all(|byte| {
        byte.is_ascii_uppercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'-' | b'_')
    }) {
        return Err(format!("invalid test id characters: {id}"));
    }
    Ok(())
}

fn new_run_id() -> String {
    let counter = RUN_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("run-{}-{}-{counter}", unix_ms(), std::process::id())
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
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
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{Artifact, Runner, SecurityTest, TestContext, TestExecution, TestRegistry};
    use crate::evidence::EvidenceLimits;
    use crate::model::{
        ExecutionModel, ExecutionPolicy, SafetyClass, TestCategory, TestDescriptor, TestStatus,
    };

    struct FixtureTest {
        descriptor: TestDescriptor,
        execution: TestExecution,
    }

    impl SecurityTest for FixtureTest {
        fn descriptor(&self) -> &TestDescriptor {
            &self.descriptor
        }

        fn execute(&self, _context: &TestContext<'_>) -> Result<TestExecution, String> {
            Ok(self.execution.clone())
        }
    }

    fn temp_root(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("dfstl-runner-{label}-{}-{nonce}", std::process::id()))
    }

    fn descriptor(id: &'static str, safety: SafetyClass) -> TestDescriptor {
        TestDescriptor::new(
            id,
            "fixture test",
            TestCategory::StaticAnalysis,
            safety,
            ExecutionModel::WhiteBox,
        )
    }

    #[test]
    fn runner_records_pass_and_artifact_and_finalizes_evidence() {
        let root = temp_root("pass");
        let mut registry = TestRegistry::new();
        registry
            .register(FixtureTest {
                descriptor: descriptor("STATIC-CORE-001", SafetyClass::Safe),
                execution: TestExecution::pass("fixture passed")
                    .with_artifact(Artifact::new("proof.txt", b"synthetic".to_vec())),
            })
            .expect("register");

        let completed = Runner::new(ExecutionPolicy::safe_only(), &root)
            .run(&registry)
            .expect("run");

        assert_eq!(completed.report.counts.pass, 1);
        assert_eq!(completed.report.counts.total(), 1);
        assert!(completed.evidence_dir.join("report.json").is_file());
        assert!(completed.evidence_dir.join("report.txt").is_file());
        assert!(completed.evidence_dir.join("SHA256SUMS").is_file());
        assert!(
            completed
                .evidence_dir
                .join("artifacts/STATIC-CORE-001/proof.txt")
                .is_file()
        );
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn runner_skips_tests_above_policy_without_executing_them() {
        let root = temp_root("skip");
        let mut registry = TestRegistry::new();
        registry
            .register(FixtureTest {
                descriptor: descriptor("FAULT-CORE-001", SafetyClass::Disruptive),
                execution: TestExecution::new(TestStatus::Fail, "must not execute"),
            })
            .expect("register");

        let completed = Runner::new(ExecutionPolicy::safe_only(), &root)
            .run(&registry)
            .expect("run");

        assert_eq!(completed.report.counts.skipped, 1);
        assert_eq!(completed.report.tests[0].status, TestStatus::Skipped);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn execution_errors_are_infrastructure_errors_not_target_failures() {
        struct BrokenTest(TestDescriptor);
        impl SecurityTest for BrokenTest {
            fn descriptor(&self) -> &TestDescriptor {
                &self.0
            }

            fn execute(&self, _context: &TestContext<'_>) -> Result<TestExecution, String> {
                Err("fixture infrastructure failure".to_owned())
            }
        }

        let root = temp_root("infra");
        let mut registry = TestRegistry::new();
        registry
            .register(BrokenTest(descriptor(
                "STATIC-CORE-002",
                SafetyClass::Safe,
            )))
            .expect("register");

        let completed = Runner::new(ExecutionPolicy::safe_only(), &root)
            .run(&registry)
            .expect("run");
        assert_eq!(completed.report.counts.infrastructure_error, 1);
        assert_eq!(completed.report.counts.fail, 0);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn runner_preserves_distinct_result_states() {
        let root = temp_root("states");
        let mut registry = TestRegistry::new();
        for (id, status) in [
            ("STATIC-STATE-001", TestStatus::Pass),
            ("STATIC-STATE-002", TestStatus::Fail),
            ("STATIC-STATE-003", TestStatus::Warning),
        ] {
            registry
                .register(FixtureTest {
                    descriptor: descriptor(id, SafetyClass::Safe),
                    execution: TestExecution::new(status, "state fixture"),
                })
                .expect("register");
        }
        registry
            .register(FixtureTest {
                descriptor: descriptor("STATIC-STATE-004", SafetyClass::Controlled),
                execution: TestExecution::pass("must be skipped"),
            })
            .expect("register");

        struct BrokenTest(TestDescriptor);
        impl SecurityTest for BrokenTest {
            fn descriptor(&self) -> &TestDescriptor {
                &self.0
            }

            fn execute(&self, _context: &TestContext<'_>) -> Result<TestExecution, String> {
                Err("fixture infrastructure error".to_owned())
            }
        }
        registry
            .register(BrokenTest(descriptor(
                "STATIC-STATE-005",
                SafetyClass::Safe,
            )))
            .expect("register");

        let completed = Runner::new(ExecutionPolicy::safe_only(), &root)
            .run(&registry)
            .expect("run");
        assert_eq!(completed.report.counts.pass, 1);
        assert_eq!(completed.report.counts.fail, 1);
        assert_eq!(completed.report.counts.warning, 1);
        assert_eq!(completed.report.counts.skipped, 1);
        assert_eq!(completed.report.counts.infrastructure_error, 1);
        assert_eq!(completed.report.counts.total(), 5);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn duplicate_test_ids_are_rejected() {
        let mut registry = TestRegistry::new();
        registry
            .register(FixtureTest {
                descriptor: descriptor("STATIC-CORE-003", SafetyClass::Safe),
                execution: TestExecution::pass("first"),
            })
            .expect("first registration");
        let second = registry.register(FixtureTest {
            descriptor: descriptor("STATIC-CORE-003", SafetyClass::Safe),
            execution: TestExecution::pass("second"),
        });
        assert!(second.is_err());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn evidence_limit_failure_is_recorded_as_infrastructure_error() {
        let root = temp_root("limit");
        let mut registry = TestRegistry::new();
        registry
            .register(FixtureTest {
                descriptor: descriptor("STATIC-CORE-004", SafetyClass::Safe),
                execution: TestExecution::pass("artifact")
                    .with_artifact(Artifact::new("large.bin", vec![0_u8; 2048])),
            })
            .expect("register");

        let limits = EvidenceLimits {
            max_file_bytes: 1024,
            max_total_bytes: 8192,
            max_files: 16,
        };
        let completed = Runner::new(ExecutionPolicy::safe_only(), &root)
            .with_evidence_limits(limits)
            .run(&registry)
            .expect("run");
        assert_eq!(completed.report.counts.infrastructure_error, 1);
        assert_eq!(completed.report.counts.fail, 0);
        fs::remove_dir_all(root).expect("cleanup");
    }
}
