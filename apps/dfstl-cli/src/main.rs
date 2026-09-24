#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;

use dfstl_core::{
    Artifact, EXPECTED_EXECUTABLES, EncryptedFormat, ExecutionModel, ExecutionPolicy,
    ExternalToolStatus, PackageManifestStatus, Runner, SafetyClass, SecurityTest, TargetError,
    TestCategory, TestContext, TestDescriptor, TestExecution, TestRegistry,
    DEFAULT_FUZZ_CASES, FuzzTarget, generate_fuzz_corpus, generate_mutation_corpus,
    generate_runtime_mutation_corpus, generate_sync_request_mutations, inspect_target,
    path_policy_corpus, promote_regression_fixture, resolve_target, run_agent_attack_harness,
    run_external_scanners, run_filesystem_lab, run_sync_api_probe, scan_source, write_scan_bundle,
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
        "source" => {
            let arguments: Vec<String> = args.collect();
            source_command(&arguments);
        }
        "format" => {
            let arguments: Vec<String> = args.collect();
            format_command(&arguments);
        }
        "agent" => {
            let arguments: Vec<String> = args.collect();
            agent_command(&arguments);
        }
        "filesystem" => {
            let arguments: Vec<String> = args.collect();
            filesystem_command(&arguments);
        }
        "sync-api" => {
            let arguments: Vec<String> = args.collect();
            sync_api_command(&arguments);
        }
        "fuzz" => {
            let arguments: Vec<String> = args.collect();
            fuzz_command(&arguments);
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
    println!("phase: 8");
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
    println!("static-source-scan: available");
    println!("dependency-inventory: available");
    println!("spdx-sbom: available");
    println!("external-scanners: cargo-audit,cargo-deny,gitleaks");
    println!("encrypted-format-mutation: available");
    println!("mutation-safety-class: controlled");
    println!("mutation-formats: dfvault,dfbackup,dfshare,dfauth,password-manager-dfvault");
    println!("agent-attack-harness: available");
    println!("agent-harness-safety-class: controlled");
    println!("agent-protocol-baseline: 1.1");
    println!("agent-runtime-mutation: cloned-only");
    println!("filesystem-path-corpus: available");
    println!("filesystem-lab: available");
    println!("filesystem-lab-safety-class: lab-only");
    println!("windows-reparse-testing: available");
    println!("toctou-race-testing: disposable-only");
    println!("password-manager-sync-api-harness: available");
    println!("sync-api-protocol-baseline: 2");
    println!("sync-api-live-safety-class: controlled");
    println!("sync-api-live-target: ipv4-loopback-only");
    println!("sync-api-request-mutation: offline-only");
    println!("deterministic-fuzz-corpus: available");
    println!("fuzz-targets: dfvault,dfbackup,dfshare,dfauth,password-manager-json,agent-json,sync-http,windows-path");
    println!("fuzz-regression-promotion: available");
    println!("fuzz-minimizer-api: available");
    println!("cargo-fuzz-scaffold: available");
    println!(concat!(
        "active-attack-implementations: encrypted-format-mutation,",
        "agent-loopback-harness,filesystem-lab"
    ));
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
        .register(StaticScanSelfCheck)
        .expect("static built-in test ID must be valid");
    registry
        .register(EncryptedFormatMutationSelfCheck)
        .expect("static built-in test ID must be valid");
    registry
        .register(AgentHarnessSelfCheck)
        .expect("static built-in test ID must be valid");
    registry
        .register(FilesystemLabSelfCheck)
        .expect("static built-in test ID must be valid");
    registry
        .register(SyncApiHarnessSelfCheck)
        .expect("static built-in test ID must be valid");
    registry
        .register(FuzzRegressionSelfCheck)
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
    let mut controlled = false;
    let mut lab_acknowledged = false;
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
            "--controlled" => controlled = true,
            "--lab-ack" => lab_acknowledged = true,
            unknown => {
                eprintln!("unknown run option: {unknown}");
                std::process::exit(2);
            }
        }
        index += 1;
    }

    let registry = registry();
    let policy = if lab_acknowledged {
        ExecutionPolicy::lab_only_acknowledged()
    } else if controlled {
        ExecutionPolicy::controlled()
    } else {
        ExecutionPolicy::safe_only()
    };
    let runner = Runner::new(policy, output);
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

fn source_command(arguments: &[String]) {
    let Some(subcommand) = arguments.first() else {
        eprintln!("source requires a subcommand: scan");
        std::process::exit(2);
    };

    match subcommand.as_str() {
        "scan" => source_scan(&arguments[1..]),
        other => {
            eprintln!("unknown source subcommand: {other}");
            std::process::exit(2);
        }
    }
}

fn source_scan(arguments: &[String]) {
    let mut source = None;
    let mut output = PathBuf::from("results/static-scan");
    let mut external = false;
    let mut json = false;
    let mut index = 0_usize;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--source" => {
                index += 1;
                let Some(path) = arguments.get(index) else {
                    eprintln!("--source requires a path");
                    std::process::exit(2);
                };
                source = Some(PathBuf::from(path));
            }
            "--output" => {
                index += 1;
                let Some(path) = arguments.get(index) else {
                    eprintln!("--output requires a path");
                    std::process::exit(2);
                };
                output = PathBuf::from(path);
            }
            "--external" => external = true,
            "--json" => json = true,
            unknown => {
                eprintln!("unknown source scan option: {unknown}");
                std::process::exit(2);
            }
        }
        index += 1;
    }

    let Some(source) = source else {
        eprintln!("source scan requires --source PATH");
        std::process::exit(2);
    };

    let report = match scan_source(&source) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("source scan failed: {error}");
            std::process::exit(3);
        }
    };

    if let Err(error) = write_scan_bundle(&output, &report) {
        eprintln!("failed to write source-scan evidence: {error}");
        std::process::exit(3);
    }

    if json {
        print!("{}", report.to_json_pretty());
    } else {
        print!("{}", report.to_text());
        println!("Evidence directory: {}", output.display());
    }

    let mut external_incomplete = false;
    let mut external_failed = false;
    if external {
        let external_dir = output.join("external");
        let results = match run_external_scanners(&source, &external_dir) {
            Ok(results) => results,
            Err(error) => {
                eprintln!("external scanner orchestration failed: {error}");
                std::process::exit(3);
            }
        };

        for result in [
            &results.cargo_audit,
            &results.cargo_deny,
            &results.gitleaks_history,
        ] {
            match result.status {
                ExternalToolStatus::Passed => {}
                ExternalToolStatus::Unavailable => external_incomplete = true,
                ExternalToolStatus::Failed(_) => external_failed = true,
            }
        }

        if !json {
            println!(
                "External scanners: cargo-audit={}, cargo-deny={}, gitleaks={}",
                results.cargo_audit.status.as_str(),
                results.cargo_deny.status.as_str(),
                results.gitleaks_history.status.as_str()
            );
        }
    }

    if report.has_high_findings() || external_failed {
        std::process::exit(1);
    }
    if report.coverage_truncated || external_incomplete {
        std::process::exit(5);
    }
}

fn format_command(arguments: &[String]) {
    let Some(subcommand) = arguments.first() else {
        eprintln!("format requires a subcommand: mutate");
        std::process::exit(2);
    };

    match subcommand.as_str() {
        "mutate" => format_mutate(&arguments[1..]),
        other => {
            eprintln!("unknown format subcommand: {other}");
            std::process::exit(2);
        }
    }
}

fn format_mutate(arguments: &[String]) {
    let mut format = None;
    let mut input = None;
    let mut output = None;
    let mut controlled = false;
    let mut json = false;
    let mut index = 0_usize;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--format" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    eprintln!("--format requires a value");
                    std::process::exit(2);
                };
                format = EncryptedFormat::from_name(value);
                if format.is_none() {
                    eprintln!("unsupported encrypted format: {value}");
                    std::process::exit(2);
                }
            }
            "--input" => {
                index += 1;
                let Some(path) = arguments.get(index) else {
                    eprintln!("--input requires a path");
                    std::process::exit(2);
                };
                input = Some(PathBuf::from(path));
            }
            "--output" => {
                index += 1;
                let Some(path) = arguments.get(index) else {
                    eprintln!("--output requires a path");
                    std::process::exit(2);
                };
                output = Some(PathBuf::from(path));
            }
            "--controlled" => controlled = true,
            "--json" => json = true,
            unknown => {
                eprintln!("unknown format mutate option: {unknown}");
                std::process::exit(2);
            }
        }
        index += 1;
    }

    if !controlled {
        eprintln!(
            "encrypted-format mutation is Controlled-class; rerun with explicit --controlled"
        );
        std::process::exit(6);
    }

    let Some(format) = format else {
        eprintln!("format mutate requires --format NAME");
        std::process::exit(2);
    };
    let Some(input) = input else {
        eprintln!("format mutate requires --input PATH");
        std::process::exit(2);
    };
    let Some(output) = output else {
        eprintln!("format mutate requires --output PATH");
        std::process::exit(2);
    };

    let corpus = match generate_mutation_corpus(&input, format, &output) {
        Ok(corpus) => corpus,
        Err(error) => {
            eprintln!("encrypted-format mutation failed: {error}");
            std::process::exit(3);
        }
    };

    if json {
        print!("{}", corpus.to_json_pretty());
    } else {
        print!("{}", corpus.to_text());
        println!("Corpus directory: {}", corpus.output_dir.display());
        println!(
            "Manifest: {}",
            corpus.output_dir.join("SHA256SUMS").display()
        );
    }
}

fn agent_command(arguments: &[String]) {
    let Some(subcommand) = arguments.first() else {
        eprintln!("agent requires a subcommand: attack or runtime-mutate");
        std::process::exit(2);
    };

    match subcommand.as_str() {
        "attack" => agent_attack(&arguments[1..]),
        "runtime-mutate" => agent_runtime_mutate(&arguments[1..]),
        other => {
            eprintln!("unknown agent subcommand: {other}");
            std::process::exit(2);
        }
    }
}

fn agent_attack(arguments: &[String]) {
    let mut runtime_dir = None;
    let mut controlled = false;
    let mut json = false;
    let mut index = 0_usize;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--runtime-dir" => {
                index += 1;
                let Some(path) = arguments.get(index) else {
                    eprintln!("--runtime-dir requires a path");
                    std::process::exit(2);
                };
                runtime_dir = Some(PathBuf::from(path));
            }
            "--controlled" => controlled = true,
            "--json" => json = true,
            unknown => {
                eprintln!("unknown agent attack option: {unknown}");
                std::process::exit(2);
            }
        }
        index += 1;
    }

    if !controlled {
        eprintln!("Agent attack harness is Controlled-class; rerun with explicit --controlled");
        std::process::exit(6);
    }

    let Some(runtime_dir) = runtime_dir else {
        eprintln!("agent attack requires --runtime-dir PATH");
        std::process::exit(2);
    };

    let report = match run_agent_attack_harness(&runtime_dir) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("Agent attack harness failed: {error}");
            std::process::exit(3);
        }
    };

    if json {
        print!("{}", report.to_json_pretty());
    } else {
        print!("{}", report.to_text());
    }

    if !report.all_expected() {
        std::process::exit(1);
    }
}

fn agent_runtime_mutate(arguments: &[String]) {
    let mut runtime_dir = None;
    let mut output = None;
    let mut controlled = false;
    let mut json = false;
    let mut index = 0_usize;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--runtime-dir" => {
                index += 1;
                let Some(path) = arguments.get(index) else {
                    eprintln!("--runtime-dir requires a path");
                    std::process::exit(2);
                };
                runtime_dir = Some(PathBuf::from(path));
            }
            "--output" => {
                index += 1;
                let Some(path) = arguments.get(index) else {
                    eprintln!("--output requires a path");
                    std::process::exit(2);
                };
                output = Some(PathBuf::from(path));
            }
            "--controlled" => controlled = true,
            "--json" => json = true,
            unknown => {
                eprintln!("unknown agent runtime-mutate option: {unknown}");
                std::process::exit(2);
            }
        }
        index += 1;
    }

    if !controlled {
        eprintln!("Agent runtime mutation is Controlled-class; rerun with explicit --controlled");
        std::process::exit(6);
    }

    let Some(runtime_dir) = runtime_dir else {
        eprintln!("agent runtime-mutate requires --runtime-dir PATH");
        std::process::exit(2);
    };
    let Some(output) = output else {
        eprintln!("agent runtime-mutate requires --output PATH");
        std::process::exit(2);
    };

    let corpus = match generate_runtime_mutation_corpus(&runtime_dir, &output) {
        Ok(corpus) => corpus,
        Err(error) => {
            eprintln!("Agent runtime mutation failed: {error}");
            std::process::exit(3);
        }
    };

    if json {
        print!("{}", corpus.to_json_pretty());
    } else {
        println!("DragonForge Agent runtime mutation corpus");
        println!("Cases: {}", corpus.cases.len());
        println!("Output: {}", output.display());
    }
}

fn filesystem_command(arguments: &[String]) {
    let Some(subcommand) = arguments.first() else {
        eprintln!("filesystem requires a subcommand: path-corpus or lab");
        std::process::exit(2);
    };

    match subcommand.as_str() {
        "path-corpus" => {
            let report = path_policy_corpus();
            print!("{}", report.to_json_pretty());
            if !report.all_expected() {
                std::process::exit(1);
            }
        }
        "lab" => filesystem_lab_command(&arguments[1..]),
        other => {
            eprintln!("unknown filesystem subcommand: {other}");
            std::process::exit(2);
        }
    }
}

fn filesystem_lab_command(arguments: &[String]) {
    let mut root = None;
    let mut lab_acknowledged = false;
    let mut json = false;
    let mut index = 0_usize;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--root" => {
                index += 1;
                let Some(path) = arguments.get(index) else {
                    eprintln!("--root requires a path");
                    std::process::exit(2);
                };
                root = Some(PathBuf::from(path));
            }
            "--lab-ack" => lab_acknowledged = true,
            "--json" => json = true,
            unknown => {
                eprintln!("unknown filesystem lab option: {unknown}");
                std::process::exit(2);
            }
        }
        index += 1;
    }

    if !lab_acknowledged {
        eprintln!("filesystem lab is LabOnly; rerun with explicit --lab-ack");
        std::process::exit(7);
    }

    let Some(root) = root else {
        eprintln!("filesystem lab requires --root PATH");
        std::process::exit(2);
    };

    let report = match run_filesystem_lab(&root) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("filesystem lab failed: {error}");
            std::process::exit(3);
        }
    };

    if json {
        print!("{}", report.to_json_pretty());
    } else {
        print!("{}", report.to_text());
        println!("Manifest: {}", root.join("SHA256SUMS").display());
    }

    if report.has_failures() {
        std::process::exit(1);
    }
}

fn sync_api_command(arguments: &[String]) {
    let Some(subcommand) = arguments.first() else {
        eprintln!("sync-api requires a subcommand: probe or mutate");
        std::process::exit(2);
    };

    match subcommand.as_str() {
        "probe" => sync_api_probe_command(&arguments[1..]),
        "mutate" => sync_api_mutate_command(&arguments[1..]),
        other => {
            eprintln!("unknown sync-api subcommand: {other}");
            std::process::exit(2);
        }
    }
}

fn sync_api_probe_command(arguments: &[String]) {
    let mut base_url = None;
    let mut controlled = false;
    let mut json = false;
    let mut index = 0_usize;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--base-url" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    eprintln!("--base-url requires a value");
                    std::process::exit(2);
                };
                base_url = Some(value.clone());
            }
            "--controlled" => controlled = true,
            "--json" => json = true,
            unknown => {
                eprintln!("unknown sync-api probe option: {unknown}");
                std::process::exit(2);
            }
        }
        index += 1;
    }

    if !controlled {
        eprintln!("sync API live probing is Controlled-class; rerun with explicit --controlled");
        std::process::exit(6);
    }

    let Some(base_url) = base_url else {
        eprintln!("sync-api probe requires --base-url http://127.0.0.1:PORT");
        std::process::exit(2);
    };

    let report = match run_sync_api_probe(&base_url) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("sync API probe failed: {error}");
            std::process::exit(3);
        }
    };

    if json {
        print!("{}", report.to_json_pretty());
    } else {
        println!("DragonForge Password Manager sync API probe");
        println!("Endpoint: {}", report.endpoint);
        println!("Protocol: {}", report.protocol_version);
        for case in &report.cases {
            println!(
                "{}  status={}  {}",
                case.id,
                case.status
                    .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                if case.passed { "pass" } else { "fail" }
            );
        }
    }

    if !report.all_expected() {
        std::process::exit(1);
    }
}

fn sync_api_mutate_command(arguments: &[String]) {
    let mut input = None;
    let mut output = None;
    let mut controlled = false;
    let mut json = false;
    let mut index = 0_usize;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--input" => {
                index += 1;
                let Some(path) = arguments.get(index) else {
                    eprintln!("--input requires a path");
                    std::process::exit(2);
                };
                input = Some(PathBuf::from(path));
            }
            "--output" => {
                index += 1;
                let Some(path) = arguments.get(index) else {
                    eprintln!("--output requires a path");
                    std::process::exit(2);
                };
                output = Some(PathBuf::from(path));
            }
            "--controlled" => controlled = true,
            "--json" => json = true,
            unknown => {
                eprintln!("unknown sync-api mutate option: {unknown}");
                std::process::exit(2);
            }
        }
        index += 1;
    }

    if !controlled {
        eprintln!(
            "sync API request mutation is Controlled-class; rerun with explicit --controlled"
        );
        std::process::exit(6);
    }

    let Some(input) = input else {
        eprintln!("sync-api mutate requires --input PATH");
        std::process::exit(2);
    };
    let Some(output) = output else {
        eprintln!("sync-api mutate requires --output PATH");
        std::process::exit(2);
    };

    let corpus = match generate_sync_request_mutations(&input, &output) {
        Ok(corpus) => corpus,
        Err(error) => {
            eprintln!("sync API request mutation failed: {error}");
            std::process::exit(3);
        }
    };

    if json {
        print!("{}", corpus.to_json_pretty());
    } else {
        println!("DragonForge sync API request mutation corpus");
        println!("Cases: {}", corpus.cases.len());
        println!("Output: {}", output.display());
        println!("Manifest: {}", output.join("SHA256SUMS").display());
    }
}


fn fuzz_command(arguments: &[String]) {
    let Some(subcommand) = arguments.first() else {
        eprintln!("fuzz requires a subcommand: corpus or promote");
        std::process::exit(2);
    };

    match subcommand.as_str() {
        "corpus" => fuzz_corpus_command(&arguments[1..]),
        "promote" => fuzz_promote_command(&arguments[1..]),
        other => {
            eprintln!("unknown fuzz subcommand: {other}");
            std::process::exit(2);
        }
    }
}

fn fuzz_corpus_command(arguments: &[String]) {
    let mut target = None;
    let mut input = None;
    let mut output = None;
    let mut seed = 0x4452_4147_4f4e_4655_u64;
    let mut count = DEFAULT_FUZZ_CASES;
    let mut controlled = false;
    let mut json = false;
    let mut index = 0_usize;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--target" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    eprintln!("--target requires a value");
                    std::process::exit(2);
                };
                target = Some(value.clone());
            }
            "--input" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    eprintln!("--input requires a path");
                    std::process::exit(2);
                };
                input = Some(PathBuf::from(value));
            }
            "--output" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    eprintln!("--output requires a path");
                    std::process::exit(2);
                };
                output = Some(PathBuf::from(value));
            }
            "--seed" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    eprintln!("--seed requires an integer");
                    std::process::exit(2);
                };
                seed = value.parse::<u64>().unwrap_or_else(|_| {
                    eprintln!("--seed must be an unsigned integer");
                    std::process::exit(2);
                });
            }
            "--count" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    eprintln!("--count requires an integer");
                    std::process::exit(2);
                };
                count = value.parse::<usize>().unwrap_or_else(|_| {
                    eprintln!("--count must be an unsigned integer");
                    std::process::exit(2);
                });
            }
            "--controlled" => controlled = true,
            "--json" => json = true,
            unknown => {
                eprintln!("unknown fuzz corpus option: {unknown}");
                std::process::exit(2);
            }
        }
        index += 1;
    }

    if !controlled {
        eprintln!("fuzz corpus generation is Controlled-class; rerun with explicit --controlled");
        std::process::exit(6);
    }

    let Some(target) = target else {
        eprintln!("fuzz corpus requires --target NAME");
        std::process::exit(2);
    };
    let target = FuzzTarget::parse(&target).unwrap_or_else(|error| {
        eprintln!("fuzz target failed: {error}");
        std::process::exit(2);
    });
    let Some(input) = input else {
        eprintln!("fuzz corpus requires --input PATH");
        std::process::exit(2);
    };
    let Some(output) = output else {
        eprintln!("fuzz corpus requires --output PATH");
        std::process::exit(2);
    };

    let corpus = generate_fuzz_corpus(target, &input, &output, seed, count).unwrap_or_else(|error| {
        eprintln!("fuzz corpus generation failed: {error}");
        std::process::exit(3);
    });

    if json {
        print!("{}", corpus.to_json_pretty());
    } else {
        println!("DragonForge deterministic fuzz corpus");
        println!("Target: {}", corpus.target);
        println!("RNG seed: {}", corpus.rng_seed);
        println!("Cases: {}", corpus.cases.len());
        println!("Output: {}", output.display());
        println!("Manifest: {}", output.join("SHA256SUMS").display());
    }
}

fn fuzz_promote_command(arguments: &[String]) {
    let mut target = None;
    let mut input = None;
    let mut regression_root = None;
    let mut note = String::new();
    let mut controlled = false;
    let mut json = false;
    let mut index = 0_usize;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--target" => {
                index += 1;
                target = arguments.get(index).cloned();
            }
            "--input" => {
                index += 1;
                input = arguments.get(index).map(PathBuf::from);
            }
            "--regression-root" => {
                index += 1;
                regression_root = arguments.get(index).map(PathBuf::from);
            }
            "--note" => {
                index += 1;
                note = arguments.get(index).cloned().unwrap_or_default();
            }
            "--controlled" => controlled = true,
            "--json" => json = true,
            unknown => {
                eprintln!("unknown fuzz promote option: {unknown}");
                std::process::exit(2);
            }
        }
        index += 1;
    }

    if !controlled {
        eprintln!("fuzz regression promotion is Controlled-class; rerun with explicit --controlled");
        std::process::exit(6);
    }

    let Some(target) = target else {
        eprintln!("fuzz promote requires --target NAME");
        std::process::exit(2);
    };
    let target = FuzzTarget::parse(&target).unwrap_or_else(|error| {
        eprintln!("fuzz target failed: {error}");
        std::process::exit(2);
    });
    let Some(input) = input else {
        eprintln!("fuzz promote requires --input PATH");
        std::process::exit(2);
    };
    let Some(regression_root) = regression_root else {
        eprintln!("fuzz promote requires --regression-root PATH");
        std::process::exit(2);
    };

    let fixture =
        promote_regression_fixture(target, &input, &regression_root, &note).unwrap_or_else(|error| {
            eprintln!("fuzz regression promotion failed: {error}");
            std::process::exit(3);
        });

    if json {
        print!("{}", fixture.to_json_pretty());
    } else {
        println!("DragonForge regression fixture promoted");
        println!("Target: {}", fixture.target);
        println!("File: {}", fixture.filename);
        println!("SHA-256: {}", fixture.sha256);
    }
}

fn help() {
    println!("DragonForge Security Test Lab");
    println!();
    println!("Usage: dfstl <command>");
    println!();
    println!("Commands:");
    println!("  describe                         Show the Phase 8 runtime model");
    println!("  list                             List registered built-in tests");
    println!("  run [--output PATH] [--controlled] [--lab-ack]");
    println!(
        "                                   Run registered tests within an explicit safety policy"
    );
    println!("  target inspect --target PATH     Identify an explicit local DragonForge build");
    println!("  source scan --source PATH        Run built-in static/dependency/secret scans");
    println!("    [--output PATH] [--json] [--external]");
    println!("  format mutate --format NAME      Generate bounded adversarial encrypted inputs");
    println!("    --input PATH --output PATH --controlled [--json]");
    println!("  agent attack --runtime-dir PATH  Exercise explicit live loopback Agent runtime");
    println!("    --controlled [--json]");
    println!("  agent runtime-mutate             Generate cloned runtime/startup-race fixtures");
    println!("    --runtime-dir PATH --output PATH --controlled [--json]");
    println!("  filesystem path-corpus           Emit deterministic Windows path-policy cases");
    println!("  filesystem lab --root PATH       Run disposable reparse/TOCTOU lab");
    println!("    --lab-ack [--json]");
    println!("  sync-api probe --base-url URL    Probe explicit local Password Manager sync API");
    println!("    --controlled [--json]");
    println!("  sync-api mutate --input PATH     Generate offline captured-request mutations");
    println!("    --output PATH --controlled [--json]");
    println!("  fuzz corpus --target NAME        Generate deterministic structure-aware corpus");
    println!("    --input PATH --output PATH --controlled [--seed N] [--count N] [--json]");
    println!("  fuzz promote --target NAME       Promote candidate into permanent regression corpus");
    println!("    --input PATH --regression-root PATH --controlled [--note TEXT] [--json]");
    println!("  version                          Show the CLI version");
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

    fn execute(&self, _context: &TestContext<'_>) -> Result<TestExecution, String> {
        let default_policy = ExecutionPolicy::default();
        if !default_policy.allows(SafetyClass::Safe)
            || default_policy.allows(SafetyClass::Controlled)
            || default_policy.allows(SafetyClass::Disruptive)
            || default_policy.allows(SafetyClass::LabOnly)
        {
            return Ok(TestExecution::new(
                dfstl_core::TestStatus::Fail,
                "default execution policy is not Safe-only",
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

struct StaticScanSelfCheck;

impl SecurityTest for StaticScanSelfCheck {
    fn descriptor(&self) -> &TestDescriptor {
        static DESCRIPTOR: TestDescriptor = TestDescriptor::new(
            "STATIC-SUPPLY-001",
            "Static scanner capability contract",
            TestCategory::SupplyChain,
            SafetyClass::Safe,
            ExecutionModel::WhiteBox,
        );
        &DESCRIPTOR
    }

    fn execute(&self, _context: &TestContext<'_>) -> Result<TestExecution, String> {
        Ok(TestExecution::pass(
            "built-in static, dependency, SBOM, supply-chain, and secret scanning is available",
        ))
    }
}

struct EncryptedFormatMutationSelfCheck;

impl SecurityTest for EncryptedFormatMutationSelfCheck {
    fn descriptor(&self) -> &TestDescriptor {
        static DESCRIPTOR: TestDescriptor = TestDescriptor::new(
            "PARSER-MUTATE-001",
            "Encrypted-format mutation capability",
            TestCategory::Parser,
            SafetyClass::Controlled,
            ExecutionModel::WhiteBox,
        );
        &DESCRIPTOR
    }

    fn execute(&self, context: &TestContext<'_>) -> Result<TestExecution, String> {
        if !context.policy.allows(SafetyClass::Controlled) {
            return Ok(TestExecution::new(
                dfstl_core::TestStatus::Fail,
                "Controlled mutation test executed without Controlled policy",
            ));
        }

        Ok(TestExecution::pass(
            "bounded encrypted-format mutation capability is authorized",
        ))
    }
}

struct AgentHarnessSelfCheck;

impl SecurityTest for AgentHarnessSelfCheck {
    fn descriptor(&self) -> &TestDescriptor {
        static DESCRIPTOR: TestDescriptor = TestDescriptor::new(
            "IPC-AGENT-001",
            "DragonForge Agent attack harness capability",
            TestCategory::LocalIpc,
            SafetyClass::Controlled,
            ExecutionModel::BlackBox,
        );
        &DESCRIPTOR
    }

    fn execute(&self, context: &TestContext<'_>) -> Result<TestExecution, String> {
        if !context.policy.allows(SafetyClass::Controlled) {
            return Ok(TestExecution::new(
                dfstl_core::TestStatus::Fail,
                "Controlled Agent harness test executed without Controlled policy",
            ));
        }

        Ok(TestExecution::pass(
            "bounded loopback Agent attack harness is authorized",
        ))
    }
}

struct FilesystemLabSelfCheck;

impl SecurityTest for FilesystemLabSelfCheck {
    fn descriptor(&self) -> &TestDescriptor {
        static DESCRIPTOR: TestDescriptor = TestDescriptor::new(
            "FS-LAB-001",
            "Filesystem reparse and TOCTOU lab capability",
            TestCategory::Filesystem,
            SafetyClass::LabOnly,
            ExecutionModel::Hybrid,
        );
        &DESCRIPTOR
    }

    fn execute(&self, context: &TestContext<'_>) -> Result<TestExecution, String> {
        if !context.policy.allows(SafetyClass::LabOnly) {
            return Ok(TestExecution::new(
                dfstl_core::TestStatus::Fail,
                "LabOnly filesystem test executed without lab acknowledgement",
            ));
        }

        Ok(TestExecution::pass(
            "disposable filesystem reparse/TOCTOU lab is explicitly authorized",
        ))
    }
}

struct SyncApiHarnessSelfCheck;

impl SecurityTest for SyncApiHarnessSelfCheck {
    fn descriptor(&self) -> &TestDescriptor {
        static DESCRIPTOR: TestDescriptor = TestDescriptor::new(
            "API-SYNC-001",
            "Password Manager sync API attack harness capability",
            TestCategory::NetworkApi,
            SafetyClass::Controlled,
            ExecutionModel::BlackBox,
        );
        &DESCRIPTOR
    }

    fn execute(&self, context: &TestContext<'_>) -> Result<TestExecution, String> {
        if !context.policy.allows(SafetyClass::Controlled) {
            return Ok(TestExecution::new(
                dfstl_core::TestStatus::Fail,
                "Controlled sync API harness executed without Controlled policy",
            ));
        }

        Ok(TestExecution::pass(
            "bounded loopback sync API attack harness is authorized",
        ))
    }
}

struct FuzzRegressionSelfCheck;

impl SecurityTest for FuzzRegressionSelfCheck {
    fn descriptor(&self) -> &TestDescriptor {
        static DESCRIPTOR: TestDescriptor = TestDescriptor::new(
            "FUZZ-CORPUS-001",
            "Deterministic fuzz and regression corpus capability",
            TestCategory::Fuzzing,
            SafetyClass::Controlled,
            ExecutionModel::WhiteBox,
        );
        &DESCRIPTOR
    }

    fn execute(&self, context: &TestContext<'_>) -> Result<TestExecution, String> {
        if !context.policy.allows(SafetyClass::Controlled) {
            return Ok(TestExecution::new(
                dfstl_core::TestStatus::Fail,
                "Controlled fuzz corpus test executed without Controlled policy",
            ));
        }

        Ok(TestExecution::pass(
            "deterministic fuzz corpus and regression promotion are authorized",
        ))
    }
}
