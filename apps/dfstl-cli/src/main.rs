#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;

use dfstl_core::{
    Artifact, EXPECTED_EXECUTABLES, ExecutionModel, ExecutionPolicy, PackageManifestStatus, Runner,
    SafetyClass, SecurityTest, TargetError, TestCategory, TestContext, TestDescriptor,
    TestExecution, TestRegistry, inspect_target, resolve_target,
};

fn main() {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".to_owned());

    match command.as_str() {
        "describe" => describe(),
        "list" => list_tests(),
        "run" => {
            let arguments: Vec<String> = args.collect();
            run_command(&arguments);
        }
        "target" => {
            let arguments: Vec<String> = args.collect();
            target_command(&arguments);
        }
        "version" | "--version" | "-V" => {
            println!("dfstl {}", env!("CARGO_PKG_VERSION"));
        }
        "help" | "--help" | "-h" => help(),
        other => {
            eprintln!("unknown command: {other}");
            help();
            std::process::exit(2);
        }
    }
}

fn describe() {
    let policy = ExecutionPolicy::default();
    println!("DragonForge Security Test Lab");
    println!("phase: 2");
    println!("default-safety-policy: {}", policy.maximum_class());
    println!(
        "controlled-allowed-by-default: {}",
        policy.allows(SafetyClass::Controlled)
    );
    println!(
        "disruptive-allowed-by-default: {}",
        policy.allows(SafetyClass::Disruptive)
    );
    println!(
        "lab-only-allowed-by-default: {}",
        policy.allows(SafetyClass::LabOnly)
    );
    println!("core-runner: available");
    println!("structured-json-reporting: available");
    println!("sha256-evidence-manifest: available");
    println!("bounded-artifacts: available");
    println!("target-discovery: available");
    println!("target-build-identification: sha256");
    println!("expected-suite-executables: {}", EXPECTED_EXECUTABLES.len());
    println!("active-attack-implementations: none");
}

fn registry() -> TestRegistry {
    let mut registry = TestRegistry::new();
    registry
        .register(RunnerSelfCheck)
        .expect("static built-in test ID must be valid");
    registry
        .register(SafetyPolicySelfCheck)
        .expect("static built-in test ID must be valid");
    registry
        .register(TargetDiscoverySelfCheck)
        .expect("static built-in test ID must be valid");
    registry
}

fn list_tests() {
    let registry = registry();
    println!("ID                    SAFETY      CATEGORY     NAME");
    for test in registry.iter() {
        let descriptor = test.descriptor();
        println!(
            "{:<21} {:<11} {:<12} {}",
            descriptor.id,
            descriptor.safety,
            descriptor.category.code(),
            descriptor.name
        );
    }
}

fn run_command(arguments: &[String]) {
    let mut output = PathBuf::from("results");
    let mut index = 0_usize;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--output" => {
                index += 1;
                let Some(path) = arguments.get(index) else {
                    eprintln!("--output requires a path");
                    std::process::exit(2);
                };
                output = PathBuf::from(path);
            }
            unknown => {
                eprintln!("unknown run option: {unknown}");
                std::process::exit(2);
            }
        }
        index += 1;
    }

    let registry = registry();
    let runner = Runner::new(ExecutionPolicy::safe_only(), output);
    let completed = match runner.run(&registry) {
        Ok(completed) => completed,
        Err(error) => {
            eprintln!("DFSTL run failed before report finalization: {error}");
            std::process::exit(3);
        }
    };

    print!("{}", completed.report.to_text());
    println!("Evidence directory: {}", completed.evidence_dir.display());
    println!(
        "Manifest: {}",
        completed.evidence_dir.join("SHA256SUMS").display()
    );
    println!(
        "JSON report: {}",
        completed.evidence_dir.join("report.json").display()
    );

    if completed.report.counts.has_failures() {
        std::process::exit(1);
    }
}

fn target_command(arguments: &[String]) {
    let Some(subcommand) = arguments.first() else {
        eprintln!("target requires a subcommand: inspect");
        std::process::exit(2);
    };

    match subcommand.as_str() {
        "inspect" => target_inspect(&arguments[1..]),
        other => {
            eprintln!("unknown target subcommand: {other}");
            std::process::exit(2);
        }
    }
}

fn target_inspect(arguments: &[String]) {
    let mut target = None;
    let mut json = false;
    let mut index = 0_usize;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--target" => {
                index += 1;
                let Some(path) = arguments.get(index) else {
                    eprintln!("--target requires a path");
                    std::process::exit(2);
                };
                target = Some(PathBuf::from(path));
            }
            "--json" => json = true,
            unknown => {
                eprintln!("unknown target inspect option: {unknown}");
                std::process::exit(2);
            }
        }
        index += 1;
    }

    let Some(target) = target else {
        eprintln!("target inspect requires --target PATH");
        std::process::exit(2);
    };

    let resolved = match resolve_target(&target) {
        Ok(path) => path,
        Err(TargetError::AmbiguousCandidates(candidates)) => {
            eprintln!("ambiguous DragonForge target; refusing automatic selection:");
            for candidate in candidates {
                eprintln!("  {}", candidate.display());
            }
            std::process::exit(4);
        }
        Err(error) => {
            eprintln!("target discovery failed: {error}");
            std::process::exit(4);
        }
    };

    let inspection = match inspect_target(&resolved) {
        Ok(inspection) => inspection,
        Err(error) => {
            eprintln!("target inspection failed: {error}");
            std::process::exit(3);
        }
    };

    if json {
        print!("{}", inspection.to_json_pretty());
    } else {
        print!("{}", inspection.to_text());
    }

    let manifest_invalid = matches!(
        inspection.manifest_status,
        PackageManifestStatus::Invalid(_)
    );
    if !inspection.complete || manifest_invalid {
        std::process::exit(1);
    }
}

fn help() {
    println!("DragonForge Security Test Lab");
    println!();
    println!("Usage: dfstl <command>");
    println!();
    println!("Commands:");
    println!("  describe                         Show the Phase 2 runtime model");
    println!("  list                             List registered built-in tests");
    println!("  run [--output PATH]              Run safe registered tests and write evidence");
    println!("  target inspect --target PATH     Identify an explicit local DragonForge build");
    println!("  version              Show the CLI version");
    println!("  help                 Show this help");
}

struct RunnerSelfCheck;

impl SecurityTest for RunnerSelfCheck {
    fn descriptor(&self) -> &TestDescriptor {
        static DESCRIPTOR: TestDescriptor = TestDescriptor::new(
            "STATIC-RUNNER-001",
            "Core runner execution path",
            TestCategory::StaticAnalysis,
            SafetyClass::Safe,
            ExecutionModel::WhiteBox,
        );
        &DESCRIPTOR
    }

    fn execute(&self, context: &TestContext<'_>) -> Result<TestExecution, String> {
        let evidence = format!(
            "run_id={}\nmaximum_safety={}\n",
            context.run_id,
            context.policy.maximum_class()
        );
        Ok(
            TestExecution::pass("runner executed a registered Safe test successfully")
                .with_artifact(Artifact::new(
                    "runner-self-check.txt",
                    evidence.into_bytes(),
                )),
        )
    }
}

struct SafetyPolicySelfCheck;

impl SecurityTest for SafetyPolicySelfCheck {
    fn descriptor(&self) -> &TestDescriptor {
        static DESCRIPTOR: TestDescriptor = TestDescriptor::new(
            "STATIC-POLICY-001",
            "Default safety-policy enforcement",
            TestCategory::StaticAnalysis,
            SafetyClass::Safe,
            ExecutionModel::WhiteBox,
        );
        &DESCRIPTOR
    }

    fn execute(&self, context: &TestContext<'_>) -> Result<TestExecution, String> {
        if context.policy.allows(SafetyClass::Controlled)
            || context.policy.allows(SafetyClass::Disruptive)
            || context.policy.allows(SafetyClass::LabOnly)
        {
            return Ok(TestExecution::new(
                dfstl_core::TestStatus::Fail,
                "default policy unexpectedly permits a higher-risk class",
            ));
        }

        Ok(TestExecution::pass(
            "default execution policy permits only Safe tests",
        ))
    }
}

struct TargetDiscoverySelfCheck;

impl SecurityTest for TargetDiscoverySelfCheck {
    fn descriptor(&self) -> &TestDescriptor {
        static DESCRIPTOR: TestDescriptor = TestDescriptor::new(
            "STATIC-TARGET-001",
            "DragonForge target discovery contract",
            TestCategory::ReleaseIntegrity,
            SafetyClass::Safe,
            ExecutionModel::WhiteBox,
        );
        &DESCRIPTOR
    }

    fn execute(&self, _context: &TestContext<'_>) -> Result<TestExecution, String> {
        if EXPECTED_EXECUTABLES.len() != 11 {
            return Ok(TestExecution::new(
                dfstl_core::TestStatus::Fail,
                "unexpected DragonForge package executable count",
            ));
        }

        Ok(TestExecution::pass(
            "target discovery contract tracks 11 current suite executables",
        ))
    }
}
