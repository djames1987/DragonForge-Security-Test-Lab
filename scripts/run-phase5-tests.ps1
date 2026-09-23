param([switch]$Release)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$LogDir = Join-Path $RepoRoot "test-logs"
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogPath = Join-Path $LogDir "phase5-validation-$Timestamp.log"
$HashPath = "$LogPath.sha256"
$RunRoot = Join-Path $RepoRoot "results\phase5-validation-$Timestamp"
$Failures = [System.Collections.Generic.List[string]]::new()
$Warnings = [System.Collections.Generic.List[string]]::new()
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function Write-Log {
    param([string]$Message = "")
    [System.IO.File]::AppendAllText($LogPath, ($Message + [Environment]::NewLine), $Utf8NoBom)
    Write-Host $Message
}

function Write-Section {
    param([string]$Title)
    Write-Log ""
    Write-Log ("=" * 78)
    Write-Log $Title
    Write-Log ("=" * 78)
}

function Assert-True {
    param([string]$Label, [bool]$Condition)
    if ($Condition) {
        Write-Log ("PASS  {0}" -f $Label)
    }
    else {
        Write-Log ("FAIL  {0}" -f $Label)
        $Failures.Add($Label)
    }
}

function Assert-Match {
    param([string]$Label, [string]$Text, [string]$Pattern)
    Assert-True $Label ($Text -match $Pattern)
}

function Capture-NativeOutput {
    param([string]$Command, [string[]]$Arguments)
    $PreviousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $Output = (& $Command @Arguments 2>&1 | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
        $ExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $PreviousPreference
    }
    [pscustomobject]@{ Output = $Output; ExitCode = $ExitCode }
}

function Invoke-LoggedCommand {
    param([string]$Name, [string]$Command, [string[]]$Arguments = @())
    Write-Section $Name
    Write-Log ("> {0} {1}" -f $Command, ($Arguments -join " "))
    $Result = Capture-NativeOutput $Command $Arguments
    if (-not [string]::IsNullOrWhiteSpace($Result.Output)) { Write-Log $Result.Output }
    Write-Log ""
    Write-Log ("Exit code: {0}" -f $Result.ExitCode)
    if ($Result.ExitCode -ne 0) { $Failures.Add("$Name failed with exit code $($Result.ExitCode)") }
    $Result
}

Push-Location $RepoRoot
try {
    Write-Section "DragonForge Security Test Lab - Phase 5 Validation"
    Write-Log ("Started:      {0}" -f (Get-Date).ToString("o"))
    Write-Log ("Repository:   {0}" -f $RepoRoot)
    Write-Log ("Log file:     {0}" -f $LogPath)
    Write-Log ("Run output:   {0}" -f $RunRoot)
    Write-Log ("PowerShell:   {0}" -f $PSVersionTable.PSVersion)
    Write-Log ("OS:           {0}" -f [System.Environment]::OSVersion.VersionString)
    Write-Log ("Release mode: {0}" -f [bool]$Release)

    Write-Section "Environment"
    foreach ($Tool in @("git", "rustc", "cargo", "rustup")) {
        Assert-True "$Tool available" ($null -ne (Get-Command $Tool -ErrorAction SilentlyContinue))
    }
    if ($Failures.Count -gt 0) { throw "Required development tooling is missing." }

    Invoke-LoggedCommand "Git version" "git" @("--version") | Out-Null
    Invoke-LoggedCommand "Rust compiler version" "rustc" @("--version", "--verbose") | Out-Null
    Invoke-LoggedCommand "Cargo version" "cargo" @("--version", "--verbose") | Out-Null

    Write-Section "Repository state"
    $Branch = (& git branch --show-current 2>&1 | Out-String).Trim()
    $Commit = (& git rev-parse HEAD 2>&1 | Out-String).Trim()
    $Status = (& git status --porcelain 2>&1 | Out-String).Trim()
    Write-Log ("Branch:       {0}" -f $Branch)
    Write-Log ("Commit:       {0}" -f $Commit)
    Assert-True "Current branch is main" ($Branch -eq "main")
    if ([string]::IsNullOrWhiteSpace($Status)) {
        Write-Log "PASS  Working tree is clean"
    }
    else {
        Write-Log "WARNING: working tree has uncommitted changes:"
        Write-Log $Status
        $Warnings.Add("Working tree was not clean")
    }

    Write-Section "Required Phase 5 files"
    foreach ($RelativePath in @(
        "crates/dfstl-core/src/agent_harness.rs",
        "apps/dfstl-cli/src/main.rs",
        "docs/PHASE_5_AGENT_HARNESS.md",
        "docs/AGENT_ATTACK_SCHEMA.md",
        "scripts/run-phase5-tests.ps1"
    )) {
        Assert-True $RelativePath (Test-Path -LiteralPath (Join-Path $RepoRoot $RelativePath) -PathType Leaf)
    }

    Invoke-LoggedCommand "Cargo metadata" "cargo" @("metadata", "--format-version", "1", "--no-deps") | Out-Null
    Invoke-LoggedCommand "Formatting" "cargo" @("fmt", "--all", "--check") | Out-Null
    Invoke-LoggedCommand "Strict Clippy" "cargo" @("clippy", "--workspace", "--all-targets", "--", "-D", "warnings") | Out-Null
    Invoke-LoggedCommand "Debug tests" "cargo" @("test", "--workspace", "--", "--nocapture") | Out-Null
    Invoke-LoggedCommand "Loopback Agent harness regression" "cargo" @(
        "test", "-p", "dfstl-core", "loopback_attack_harness_exercises_expected_matrix", "--", "--nocapture"
    ) | Out-Null
    Invoke-LoggedCommand "RFC 4231 HMAC regression" "cargo" @(
        "test", "-p", "dfstl-core", "hmac_matches_rfc4231_vector", "--", "--nocapture"
    ) | Out-Null
    if ($Release) {
        Invoke-LoggedCommand "Release tests" "cargo" @("test", "--workspace", "--release", "--", "--nocapture") | Out-Null
    }

    Invoke-LoggedCommand "Debug CLI build" "cargo" @("build", "-p", "dfstl-cli") | Out-Null
    $CliPath = Join-Path $RepoRoot "target\debug\dfstl-cli.exe"
    Assert-True "debug DFSTL CLI exists" (Test-Path -LiteralPath $CliPath -PathType Leaf)

    Write-Section "CLI Phase 5 model"
    $Describe = Capture-NativeOutput $CliPath @("describe")
    Write-Log $Describe.Output
    Write-Log ("Exit code: {0}" -f $Describe.ExitCode)
    Assert-True "describe exits successfully" ($Describe.ExitCode -eq 0)
    Assert-Match "Phase marker is 5" $Describe.Output "phase:\s*5"
    Assert-Match "Agent harness advertised" $Describe.Output "agent-attack-harness:\s*available"
    Assert-Match "Agent harness is Controlled" $Describe.Output "agent-harness-safety-class:\s*controlled"
    Assert-Match "Agent protocol baseline is 1.1" $Describe.Output "agent-protocol-baseline:\s*1\.1"
    Assert-Match "Runtime mutation is cloned-only" $Describe.Output "agent-runtime-mutation:\s*cloned-only"

    Write-Section "Registered tests and safety"
    $List = Capture-NativeOutput $CliPath @("list")
    Write-Log $List.Output
    Write-Log ("Exit code: {0}" -f $List.ExitCode)
    Assert-True "list exits successfully" ($List.ExitCode -eq 0)
    Assert-Match "Phase 5 Agent test registered" $List.Output "IPC-AGENT-001\s+controlled\s+IPC"

    if (Test-Path -LiteralPath $RunRoot) { Remove-Item -LiteralPath $RunRoot -Recurse -Force }
    $RuntimeDir = Join-Path $RunRoot "synthetic-runtime"
    $MutationDir = Join-Path $RunRoot "runtime-mutations"
    New-Item -ItemType Directory -Force -Path $RuntimeDir | Out-Null

    $RuntimeJson = @"
{
  "format_version": 1,
  "protocol_major": 1,
  "protocol_minor": 1,
  "port": 6553,
  "pid": 4242,
  "started_at_ms": 1
}
"@
    [System.IO.File]::WriteAllText((Join-Path $RuntimeDir "agent-runtime.json"), $RuntimeJson, $Utf8NoBom)
    $KeyBytes = [byte[]](1..32 | ForEach-Object { 9 })
    $Credential = [Convert]::ToBase64String($KeyBytes) + [Environment]::NewLine
    [System.IO.File]::WriteAllText((Join-Path $RuntimeDir "agent-session.key"), $Credential, $Utf8NoBom)

    $RuntimeBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $RuntimeDir "agent-runtime.json")).Hash
    $KeyBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $RuntimeDir "agent-session.key")).Hash

    Write-Section "Controlled authorization gate"
    $Denied = Capture-NativeOutput $CliPath @("agent", "attack", "--runtime-dir", $RuntimeDir)
    Write-Log $Denied.Output
    Write-Log ("Exit code: {0}" -f $Denied.ExitCode)
    Assert-True "Agent attack without --controlled is refused" ($Denied.ExitCode -eq 6)

    Write-Section "Runtime mutation corpus"
    $Mutation = Capture-NativeOutput $CliPath @(
        "agent", "runtime-mutate",
        "--runtime-dir", $RuntimeDir,
        "--output", $MutationDir,
        "--controlled",
        "--json"
    )
    Write-Log $Mutation.Output
    Write-Log ("Exit code: {0}" -f $Mutation.ExitCode)
    Assert-True "runtime mutation exits successfully" ($Mutation.ExitCode -eq 0)
    try {
        $Corpus = $Mutation.Output | ConvertFrom-Json
        Assert-True "runtime mutation schema_version is 1" ($Corpus.schema_version -eq 1)
        Assert-True "runtime mutation has eight cases" ($Corpus.cases.Count -eq 8)
        foreach ($Id in @(
            "descriptor-empty",
            "descriptor-malformed",
            "descriptor-oversized",
            "credential-empty",
            "credential-malformed-base64",
            "credential-wrong-length",
            "startup-fresh-lock",
            "startup-stale-lock"
        )) {
            Assert-True "runtime mutation includes $Id" (@($Corpus.cases | Where-Object { $_.id -eq $Id }).Count -eq 1)
        }
    }
    catch {
        Write-Log ("FAIL  runtime mutation JSON parsing failed: {0}" -f $_.Exception.Message)
        $Failures.Add("runtime mutation JSON validation")
    }

    $RuntimeAfter = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $RuntimeDir "agent-runtime.json")).Hash
    $KeyAfter = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $RuntimeDir "agent-session.key")).Hash
    Assert-True "source runtime descriptor remains unchanged" ($RuntimeBefore -eq $RuntimeAfter)
    Assert-True "source session credential remains unchanged" ($KeyBefore -eq $KeyAfter)

    Write-Section "Safe runner enforcement"
    $SafeRun = Capture-NativeOutput $CliPath @("run", "--output", (Join-Path $RunRoot "safe-runner"))
    Write-Log $SafeRun.Output
    Write-Log ("Exit code: {0}" -f $SafeRun.ExitCode)
    Assert-True "Safe runner exits successfully" ($SafeRun.ExitCode -eq 0)
    Assert-Match "Agent harness skipped under Safe policy" $SafeRun.Output "IPC-AGENT-001\s+skipped"

    Write-Section "Controlled runner enforcement"
    $ControlledRun = Capture-NativeOutput $CliPath @(
        "run", "--controlled", "--output", (Join-Path $RunRoot "controlled-runner")
    )
    Write-Log $ControlledRun.Output
    Write-Log ("Exit code: {0}" -f $ControlledRun.ExitCode)
    Assert-True "Controlled runner exits successfully" ($ControlledRun.ExitCode -eq 0)
    Assert-Match "Agent harness self-check passes" $ControlledRun.Output "IPC-AGENT-001\s+pass"

    Invoke-LoggedCommand "Release build" "cargo" @("build", "--workspace", "--release") | Out-Null

    Write-Section "Final result"
    Write-Log ("Finished:     {0}" -f (Get-Date).ToString("o"))
    Write-Log ("Commit:       {0}" -f $Commit)
    Write-Log ("Warnings:     {0}" -f $Warnings.Count)
    Write-Log ("Failures:     {0}" -f $Failures.Count)

    if ($Warnings.Count -gt 0) {
        Write-Log ""
        Write-Log "Warnings:"
        foreach ($Warning in $Warnings) { Write-Log ("  - {0}" -f $Warning) }
    }
    if ($Failures.Count -gt 0) {
        Write-Log ""
        Write-Log "Failures:"
        foreach ($Failure in $Failures) { Write-Log ("  - {0}" -f $Failure) }
        Write-Log ""
        Write-Log "PHASE 5 VALIDATION: FAIL"
    }
    else {
        Write-Log ""
        Write-Log "PHASE 5 VALIDATION: PASS"
    }
}
catch {
    Write-Section "Validation script failure"
    Write-Log ("ERROR: {0}" -f $_.Exception.Message)
    $Failures.Add($_.Exception.Message)
    Write-Log ""
    Write-Log "PHASE 5 VALIDATION: FAIL"
}
finally {
    Pop-Location
    if (Test-Path -LiteralPath $LogPath -PathType Leaf) {
        $Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $LogPath).Hash.ToUpperInvariant()
        "$Hash  $(Split-Path -Leaf $LogPath)" | Set-Content -LiteralPath $HashPath -Encoding ASCII
        Write-Host ""
        Write-Host ("Validation log: {0}" -f $LogPath)
        Write-Host ("SHA-256:        {0}" -f $Hash)
        Write-Host ("Hash file:      {0}" -f $HashPath)
    }
}
if ($Failures.Count -gt 0) { exit 1 }
exit 0
