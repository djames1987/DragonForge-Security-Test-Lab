param([switch]$Release)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$LogDir = Join-Path $RepoRoot "test-logs"
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogPath = Join-Path $LogDir "phase10-validation-$Stamp.log"
$HashPath = "$LogPath.sha256"
$RunRoot = Join-Path $RepoRoot "results\phase10-validation-$Stamp"
$Failures = [System.Collections.Generic.List[string]]::new()
$Warnings = [System.Collections.Generic.List[string]]::new()
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function Log([string]$Text = "") {
    [System.IO.File]::AppendAllText($LogPath, ($Text + [Environment]::NewLine), $Utf8NoBom)
    Write-Host $Text
}
function Section([string]$Text) {
    Log ""
    Log ("=" * 78)
    Log $Text
    Log ("=" * 78)
}
function Pass([string]$Text, [bool]$Ok) {
    if ($Ok) { Log ("PASS  " + $Text) }
    else { Log ("FAIL  " + $Text); $Failures.Add($Text) }
}
function Capture([string]$Command, [string[]]$Arguments) {
    $Old = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $Out = (& $Command @Arguments 2>&1 | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
        $Code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $Old }
    [pscustomobject]@{ Output = $Out; ExitCode = $Code }
}
function Native([string]$Name, [string]$Command, [string[]]$Arguments) {
    Section $Name
    Log ("> " + $Command + " " + ($Arguments -join " "))
    $Result = Capture $Command $Arguments
    if ($Result.Output) { Log $Result.Output }
    Log ("Exit code: " + $Result.ExitCode)
    if ($Result.ExitCode -ne 0) {
        $Failures.Add($Name + " failed with exit code " + $Result.ExitCode)
    }
    $Result
}
function ValidateManifest([string]$Root) {
    $Manifest = Join-Path $Root "SHA256SUMS"
    Pass "SHA256SUMS exists" (Test-Path -LiteralPath $Manifest -PathType Leaf)
    if (-not (Test-Path -LiteralPath $Manifest -PathType Leaf)) { return }
    foreach ($Line in Get-Content -LiteralPath $Manifest) {
        if ([string]::IsNullOrWhiteSpace($Line)) { continue }
        $Parts = $Line -split '  ', 2
        Pass "manifest line has hash and path" ($Parts.Count -eq 2)
        if ($Parts.Count -ne 2) { continue }
        $Target = Join-Path $Root $Parts[1]
        Pass ("manifest target exists: " + $Parts[1]) (Test-Path -LiteralPath $Target -PathType Leaf)
        if (Test-Path -LiteralPath $Target -PathType Leaf) {
            $Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Target).Hash.ToLowerInvariant()
            Pass ("manifest hash matches: " + $Parts[1]) ($Actual -eq $Parts[0].ToLowerInvariant())
        }
    }
}

Push-Location $RepoRoot
try {
    Section "DragonForge Security Test Lab - Phase 10 Validation"
    Log ("Started:      " + (Get-Date).ToString("o"))
    Log ("Repository:   " + $RepoRoot)
    Log ("Log file:     " + $LogPath)
    Log ("Run output:   " + $RunRoot)
    Log ("Release mode: " + [bool]$Release)

    Section "Environment"
    foreach ($Tool in @("git","rustc","cargo","rustup")) {
        Pass ($Tool + " available") ($null -ne (Get-Command $Tool -ErrorAction SilentlyContinue))
    }
    if ($Failures.Count -gt 0) { throw "Required development tooling is missing." }

    Native "Git version" "git" @("--version") | Out-Null
    Native "Rust compiler version" "rustc" @("--version","--verbose") | Out-Null
    Native "Cargo version" "cargo" @("--version","--verbose") | Out-Null

    Section "Repository state"
    $Branch = (& git branch --show-current 2>&1 | Out-String).Trim()
    $Commit = (& git rev-parse HEAD 2>&1 | Out-String).Trim()
    $Status = (& git status --porcelain 2>&1 | Out-String).Trim()
    Log ("Branch:       " + $Branch)
    Log ("Commit:       " + $Commit)
    Pass "Current branch is main" ($Branch -eq "main")
    if ([string]::IsNullOrWhiteSpace($Status)) { Log "PASS  Working tree is clean" }
    else { Log $Status; $Warnings.Add("Working tree was not clean") }

    Section "Required Phase 10 files"
    foreach ($Path in @(
        "crates/dfstl-core/src/failure_lab.rs",
        "docs/PHASE_10_FAILURE_RESOURCE.md",
        "docs/FAILURE_RESOURCE_SCHEMA.md",
        "scripts/run-phase10-tests.ps1"
    )) { Pass $Path (Test-Path -LiteralPath (Join-Path $RepoRoot $Path) -PathType Leaf) }

    Native "Cargo metadata" "cargo" @("metadata","--format-version","1","--no-deps") | Out-Null
    Native "Formatting" "cargo" @("fmt","--all","--check") | Out-Null
    Native "Strict Clippy" "cargo" @("clippy","--workspace","--all-targets","--","-D","warnings") | Out-Null
    Native "Debug tests" "cargo" @("test","--workspace","--","--nocapture") | Out-Null
    Native "Failure injection regression" "cargo" @(
        "test","-p","dfstl-core","failure_injection_matrix_preserves_recovery_invariants","--","--nocapture"
    ) | Out-Null
    Native "Resource stress regression" "cargo" @(
        "test","-p","dfstl-core","resource_stress_is_bounded_and_completes","--","--nocapture"
    ) | Out-Null
    Native "Failure evidence regression" "cargo" @(
        "test","-p","dfstl-core","evidence_bundle_hash_manifest_is_written","--","--nocapture"
    ) | Out-Null
    if ($Release) { Native "Release tests" "cargo" @("test","--workspace","--release","--","--nocapture") | Out-Null }

    $Cli = Join-Path $RepoRoot "target\release\dfstl-cli.exe"
    if (Test-Path -LiteralPath $Cli) { Remove-Item -LiteralPath $Cli -Force }
    Native "Fresh release CLI build" "cargo" @("build","-p","dfstl-cli","--release") | Out-Null
    Pass "fresh release DFSTL CLI exists" (Test-Path -LiteralPath $Cli -PathType Leaf)
    if (-not (Test-Path -LiteralPath $Cli -PathType Leaf)) { throw "Fresh Phase 10 CLI build missing." }

    Section "CLI Phase 10 model"
    $Describe = Capture $Cli @("describe")
    Log $Describe.Output
    Pass "describe exits successfully" ($Describe.ExitCode -eq 0)
    Pass "Phase marker is 10" ($Describe.Output -match "phase:\s*10")
    Pass "failure injection advertised" ($Describe.Output -match "failure-injection-lab:\s*available")
    Pass "failure injection is Controlled" ($Describe.Output -match "failure-injection-safety-class:\s*controlled")
    Pass "resource stress advertised" ($Describe.Output -match "bounded-resource-stress:\s*cpu,memory,loopback-sockets")
    Pass "resource stress is LabOnly" ($Describe.Output -match "resource-stress-safety-class:\s*lab-only")
    Pass "self-child termination advertised" ($Describe.Output -match "self-child-termination:\s*available")
    Pass "process termination is LabOnly" ($Describe.Output -match "process-termination-safety-class:\s*lab-only")

    $List = Capture $Cli @("list")
    Log $List.Output
    Pass "FAULT injection test registered" ($List.Output -match "FAULT-INJECT-001\s+controlled\s+FAULT")
    Pass "RESOURCE test registered" ($List.Output -match "RESOURCE-LAB-001\s+lab-only\s+RESOURCE")
    Pass "FAULT kill test registered" ($List.Output -match "FAULT-KILL-001\s+lab-only\s+FAULT")

    if (Test-Path -LiteralPath $RunRoot) { Remove-Item -LiteralPath $RunRoot -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $RunRoot | Out-Null

    Section "Authorization gates"
    $DeniedInject = Capture $Cli @(
        "failure","inject","--root",(Join-Path $RunRoot "denied-lab"),
        "--output",(Join-Path $RunRoot "denied-evidence")
    )
    Log $DeniedInject.Output
    Pass "failure injection without --controlled is refused" ($DeniedInject.ExitCode -eq 6)

    $DeniedResource = Capture $Cli @(
        "failure","resource","--output",(Join-Path $RunRoot "denied-resource")
    )
    Log $DeniedResource.Output
    Pass "resource stress without --lab-ack is refused" ($DeniedResource.ExitCode -eq 7)

    $DeniedKill = Capture $Cli @("failure","process-termination")
    Log $DeniedKill.Output
    Pass "process termination without --lab-ack is refused" ($DeniedKill.ExitCode -eq 7)

    Section "Controlled failure injection"
    $FailureRoot = Join-Path $RunRoot "failure-lab"
    $FailureOut = Join-Path $RunRoot "failure-evidence"
    $Failure = Capture $Cli @(
        "failure","inject","--root",$FailureRoot,"--output",$FailureOut,"--controlled","--json"
    )
    Log $Failure.Output
    Pass "failure injection succeeds" ($Failure.ExitCode -eq 0)
    try {
        $FailureJson = $Failure.Output | ConvertFrom-Json
        Pass "failure schema_version is 1" ($FailureJson.schema_version -eq 1)
        Pass "all failure cases passed" ($FailureJson.all_passed)
        Pass "failure matrix has four cases" ($FailureJson.cases.Count -eq 4)
        foreach ($Id in @(
            "disk-full-write",
            "permission-denied-write",
            "interrupted-atomic-write",
            "interrupted-restore-recovery"
        )) {
            Pass ("failure matrix includes " + $Id) (@($FailureJson.cases | Where-Object { $_.id -eq $Id -and $_.passed }).Count -eq 1)
        }
    } catch { $Failures.Add("failure injection JSON validation") }
    Pass "committed atomic state remains stable" ((Get-Content -LiteralPath (Join-Path $FailureRoot "atomic-state.bin") -Raw) -eq "stable-state")
    Pass "interrupted staging file was removed" (-not (Test-Path -LiteralPath (Join-Path $FailureRoot "atomic-state.bin.tmp")))
    Pass "restore destination remains intact" (Test-Path -LiteralPath (Join-Path $FailureRoot "restore-destination\existing.txt") -PathType Leaf)
    Pass "partial restore staging was removed" (-not (Test-Path -LiteralPath (Join-Path $FailureRoot "restore-staging")))
    ValidateManifest $FailureOut

    Section "Bounded resource stress"
    $OverBudget = Capture $Cli @(
        "failure","resource","--output",(Join-Path $RunRoot "over-budget"),
        "--lab-ack","--memory-bytes","67108865"
    )
    Log $OverBudget.Output
    Pass "over-budget resource stress fails closed" ($OverBudget.ExitCode -eq 3)
    Pass "over-budget evidence was not created" (-not (Test-Path -LiteralPath (Join-Path $RunRoot "over-budget")))

    $ResourceOut = Join-Path $RunRoot "resource-evidence"
    $Resource = Capture $Cli @(
        "failure","resource","--output",$ResourceOut,"--lab-ack",
        "--cpu","25000","--memory-bytes","1048576","--sockets","16","--json"
    )
    Log $Resource.Output
    Pass "bounded resource stress succeeds" ($Resource.ExitCode -eq 0)
    try {
        $ResourceJson = $Resource.Output | ConvertFrom-Json
        Pass "resource schema_version is 1" ($ResourceJson.schema_version -eq 1)
        Pass "resource CPU budget recorded" ($ResourceJson.cpu_iterations -eq 25000)
        Pass "resource memory budget recorded" ($ResourceJson.memory_bytes -eq 1048576)
        Pass "resource socket budget recorded" ($ResourceJson.socket_connections -eq 16)
        Pass "resource report passed" ($ResourceJson.passed)
        Pass "resource checksum is SHA-256 shaped" ($ResourceJson.checksum -match '^[0-9a-f]{64}$')
    } catch { $Failures.Add("resource stress JSON validation") }
    ValidateManifest $ResourceOut

    Section "Self-child process termination"
    $Kill = Capture $Cli @("failure","process-termination","--lab-ack","--json")
    Log $Kill.Output
    Pass "self-child process termination succeeds" ($Kill.ExitCode -eq 0)
    try {
        $KillJson = $Kill.Output | ConvertFrom-Json
        Pass "termination target is self-child" ($KillJson.target -eq "self-child")
        Pass "worker was running before kill" ($KillJson.running_before_kill)
        Pass "kill was requested" ($KillJson.kill_requested)
        Pass "child cleanup completed" ($KillJson.wait_completed)
        Pass "termination result passed" ($KillJson.passed)
    } catch { $Failures.Add("process termination JSON validation") }

    Section "Runner safety regression"
    $Safe = Capture $Cli @("run","--output",(Join-Path $RunRoot "safe"))
    Log $Safe.Output
    Pass "Safe runner succeeds" ($Safe.ExitCode -eq 0)
    Pass "FAULT injection skipped under Safe" ($Safe.Output -match "FAULT-INJECT-001\s+skipped")
    Pass "RESOURCE skipped under Safe" ($Safe.Output -match "RESOURCE-LAB-001\s+skipped")
    Pass "FAULT kill skipped under Safe" ($Safe.Output -match "FAULT-KILL-001\s+skipped")

    $Controlled = Capture $Cli @("run","--controlled","--output",(Join-Path $RunRoot "controlled"))
    Log $Controlled.Output
    Pass "Controlled runner succeeds" ($Controlled.ExitCode -eq 0)
    Pass "FAULT injection passes under Controlled" ($Controlled.Output -match "FAULT-INJECT-001\s+pass")
    Pass "RESOURCE remains skipped under Controlled" ($Controlled.Output -match "RESOURCE-LAB-001\s+skipped")
    Pass "FAULT kill remains skipped under Controlled" ($Controlled.Output -match "FAULT-KILL-001\s+skipped")

    $Lab = Capture $Cli @("run","--lab-ack","--output",(Join-Path $RunRoot "lab"))
    Log $Lab.Output
    Pass "LabOnly runner succeeds" ($Lab.ExitCode -eq 0)
    Pass "FAULT injection passes under LabOnly" ($Lab.Output -match "FAULT-INJECT-001\s+pass")
    Pass "RESOURCE passes under LabOnly" ($Lab.Output -match "RESOURCE-LAB-001\s+pass")
    Pass "FAULT kill passes under LabOnly" ($Lab.Output -match "FAULT-KILL-001\s+pass")

    Native "Release build" "cargo" @("build","--workspace","--release") | Out-Null

    Section "Final result"
    Log ("Finished:     " + (Get-Date).ToString("o"))
    Log ("Commit:       " + $Commit)
    Log ("Warnings:     " + $Warnings.Count)
    Log ("Failures:     " + $Failures.Count)
    if ($Failures.Count -eq 0) { Log ""; Log "PHASE 10 VALIDATION: PASS" }
    else {
        Log ""
        Log "Failures:"
        foreach ($FailureItem in $Failures) { Log ("  - " + $FailureItem) }
        Log ""
        Log "PHASE 10 VALIDATION: FAIL"
    }
}
catch {
    Section "Validation script failure"
    Log ("ERROR: " + $_.Exception.Message)
    $Failures.Add($_.Exception.Message)
    Log ""
    Log "PHASE 10 VALIDATION: FAIL"
}
finally {
    Pop-Location
    if (Test-Path -LiteralPath $LogPath) {
        $Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $LogPath).Hash.ToUpperInvariant()
        ($Hash + "  " + (Split-Path -Leaf $LogPath)) | Set-Content -LiteralPath $HashPath -Encoding ASCII
        Write-Host ""
        Write-Host ("Validation log: " + $LogPath)
        Write-Host ("SHA-256:        " + $Hash)
        Write-Host ("Hash file:      " + $HashPath)
    }
}
if ($Failures.Count -gt 0) { exit 1 }
exit 0
