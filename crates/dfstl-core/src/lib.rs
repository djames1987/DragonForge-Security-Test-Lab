#![forbid(unsafe_code)]

pub mod agent_harness;
pub mod encrypted_formats;
pub mod evidence;
pub mod failure_lab;
pub mod filesystem_lab;
pub mod fuzzing;
pub mod hash;
pub mod model;
pub mod runner;
pub mod secret_leak;
pub mod static_scan;
pub mod sync_api;
pub mod target;

pub use agent_harness::{
    AGENT_PROTOCOL_MAJOR, AGENT_PROTOCOL_MINOR, AgentAttackReport, AgentHarnessError, AgentRuntime,
    AttackCaseResult, AttackOutcome, MAX_ATTACK_CASES,
    MAX_CLOCK_SKEW_MS as AGENT_MAX_CLOCK_SKEW_MS, MAX_WIRE_BYTES as AGENT_MAX_WIRE_BYTES,
    NONCE_BYTES as AGENT_NONCE_BYTES, RuntimeMutationCase, RuntimeMutationCorpus,
    SESSION_KEY_BYTES as AGENT_SESSION_KEY_BYTES, generate_runtime_mutation_corpus,
    run_agent_attack_harness,
};
pub use encrypted_formats::{
    EncryptedFormat, MAX_SEED_BYTES, MutationCase, MutationCorpus, MutationError,
    generate_mutation_corpus,
};
pub use evidence::{EvidenceError, EvidenceLimits, EvidenceSession};
pub use failure_lab::{
    DEFAULT_CPU_ITERATIONS, DEFAULT_MEMORY_BYTES, DEFAULT_SOCKET_CONNECTIONS,
    FailureInjectionReport, FailureLabError, FaultCase, MAX_CPU_ITERATIONS, MAX_MEMORY_BYTES,
    MAX_SOCKET_CONNECTIONS, ResourceStressReport, run_bounded_resource_stress,
    run_failure_injection_lab, write_failure_bundle,
};
pub use filesystem_lab::{
    FilesystemLabError, FilesystemLabReport, LabCase, LabCaseStatus, MAX_LAB_CASES, PathCorpusCase,
    PathCorpusReport, path_policy_corpus, run_filesystem_lab, validate_windows_relative_path,
};
pub use fuzzing::{
    DEFAULT_FUZZ_CASES, FuzzCase, FuzzCorpus, FuzzError, FuzzTarget, MAX_FUZZ_CASES,
    MAX_FUZZ_SEED_BYTES, RegressionFixture, exercise_fuzz_input, generate_fuzz_corpus,
    minimize_with_oracle, promote_regression_fixture,
};
pub use hash::{Sha256, hex_digest, sha256_bytes, sha256_file};
pub use model::{
    ExecutionModel, ExecutionPolicy, SafetyClass, TestCategory, TestDescriptor, TestStatus,
};
pub use runner::{
    Artifact, CompletedRun, RunCounts, RunReport, Runner, SecurityTest, TestContext, TestExecution,
    TestRecord, TestRegistry,
};
pub use secret_leak::{
    LeakFinding, MAX_FILE_SCAN_BYTES, MAX_SCAN_FILES, MAX_SENTINEL_BYTES, MAX_SENTINEL_FILE_BYTES,
    MAX_SENTINELS, MAX_TOTAL_SCAN_BYTES, SecretLeakError, SecretLeakReport, SecretSentinel,
    load_sentinels, scan_artifact_roots, scan_process_dump, synthetic_memory_lifecycle_check,
    write_secret_leak_bundle,
};
pub use static_scan::{
    DependencyRecord, ExternalScanResults, ExternalToolResult, ExternalToolStatus, FindingSeverity,
    ScanCounts, StaticFinding, StaticScanError, StaticScanReport, dependency_inventory_json,
    run_external_scanners, scan_source, spdx_json, write_scan_bundle,
};
pub use sync_api::{
    MAX_CAPTURE_BYTES, RequestMutationCase, RequestMutationCorpus, SYNC_BLOB_BYTES,
    SYNC_PROTOCOL_VERSION, SYNC_REQUEST_LIMIT_BYTES, SyncApiError, SyncApiProbeReport,
    generate_sync_request_mutations, run_sync_api_probe,
};
pub use target::{
    BuildInfo, EXPECTED_EXECUTABLES, PackageManifestStatus, TargetError, TargetExecutable,
    TargetInspection, discover_candidates, inspect_target, resolve_target,
};

#[cfg(test)]
mod phase0_regression_tests {
    use super::{ExecutionPolicy, SafetyClass};

    #[test]
    fn default_policy_is_safe_only() {
        let policy = ExecutionPolicy::default();
        assert!(policy.allows(SafetyClass::Safe));
        assert!(!policy.allows(SafetyClass::Controlled));
        assert!(!policy.allows(SafetyClass::Disruptive));
        assert!(!policy.allows(SafetyClass::LabOnly));
    }

    #[test]
    fn controlled_policy_does_not_allow_disruptive_or_lab_tests() {
        let policy = ExecutionPolicy::controlled();
        assert!(policy.allows(SafetyClass::Safe));
        assert!(policy.allows(SafetyClass::Controlled));
        assert!(!policy.allows(SafetyClass::Disruptive));
        assert!(!policy.allows(SafetyClass::LabOnly));
    }

    #[test]
    fn disruptive_policy_still_rejects_lab_only_without_lab_acknowledgement() {
        let policy = ExecutionPolicy::disruptive();
        assert!(policy.allows(SafetyClass::Disruptive));
        assert!(!policy.allows(SafetyClass::LabOnly));
    }

    #[test]
    fn explicit_lab_policy_allows_all_classes() {
        let policy = ExecutionPolicy::lab_only_acknowledged();
        assert!(policy.allows(SafetyClass::Safe));
        assert!(policy.allows(SafetyClass::Controlled));
        assert!(policy.allows(SafetyClass::Disruptive));
        assert!(policy.allows(SafetyClass::LabOnly));
    }

    #[test]
    fn safety_classes_are_monotonic() {
        assert!(SafetyClass::Safe < SafetyClass::Controlled);
        assert!(SafetyClass::Controlled < SafetyClass::Disruptive);
        assert!(SafetyClass::Disruptive < SafetyClass::LabOnly);
    }
}
