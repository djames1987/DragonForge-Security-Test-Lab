param(
    [switch]$Release
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$LogDir = Join-Path $RepoRoot "test-logs"
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogPath = Join-Path $LogDir "phase2-validation-$Timestamp.log"
$HashPath = "$LogPath.sha256"
$RunRoot = Join-Path $RepoRoot "results\phase2-validation-$Timestamp"
$FixtureRoot = Join-Path $RunRoot "fixtures"
$Failures = [System.Collections.Generic.List[string]]::new()
$Warnings = [System.Collections.Generic.List[string]]::new()
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

$ExpectedExecutables = @(
    "dragonforge-desktop.exe",
    "dragonforge-security-center.exe",
    "dragonforge-file-vault.exe",
    "dragonforge-authenticator.exe",
    "dragonforge-security-scanner.exe",
    "dragonforge-integrity-monitor.exe",
    "dragonforge-network-guard.exe",
    "dragonforge-backup-recovery.exe",
    "dragonforge-secure-share.exe",
    "dragonforge-agent.exe",
    "dragonforge-privileged-service.exe"
)

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

    return [pscustomobject]@{
        Output = $Output
        ExitCode = $ExitCode
    }
}

function Invoke-LoggedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter()][string[]]$Arguments = @()
    )

    Write-Section $Name
    Write-Log ("> {0} {1}" -f $Command, ($Arguments -join " "))
    $Result = Capture-NativeOutput $Command $Arguments
    if (-not [string]::IsNullOrWhiteSpace($Result.Output)) {
        Write-Log $Result.Output
    }
    Write-Log ""
    Write-Log ("Exit code: {0}" -f $Result.ExitCode)
    if ($Result.ExitCode -ne 0) {
        $Failures.Add("$Name failed with exit code $($Result.ExitCode)")
    }
    return $Result.ExitCode
}

function New-SyntheticTarget {
    param([string]$Path, [switch]$WithMetadata, [switch]$WithManifest)

    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    $Index = 0
    foreach ($Name in $ExpectedExecutables) {
        [System.IO.File]::WriteAllText(
            (Join-Path $Path $Name),
            ("synthetic-dragonforge-executable-{0}-{1}" -f $Index, $Name),
            $Utf8NoBom
        )
        $Index++
    }

    if ($WithMetadata) {
        $BuildInfo = @"
DragonForge Security Suite
Version: v9.9.9-dfstl
Release channel: validation
Git commit: 0123456789abcdef0123456789abcdef01234567
Git tag: v9.9.9-dfstl
Built (UTC): 2026-09-23T00:00:00Z
Platform: Windows x64 portable
Code signing: synthetic validation fixture
"@
        [System.IO.File]::WriteAllText((Join-Path $Path "BUILD-INFO.txt"), $BuildInfo, $Utf8NoBom)
    }

    if ($WithManifest) {
        $Lines = @()
        Get-ChildItem -LiteralPath $Path -File |
            Where-Object { $_.Name -ne "SHA256SUMS.txt" } |
            Sort-Object Name |
            ForEach-Object {
                $Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
                $Lines += "$Hash  $($_.Name)"
            }
        [System.IO.File]::WriteAllLines((Join-Path $Path "SHA256SUMS.txt"), $Lines, [System.Text.Encoding]::ASCII)
    }
}

Push-Location $RepoRoot
try {
    Write-Section "DragonForge Security Test Lab - Phase 2 Validation"
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
    if ($Failures.Count -gt 0) {
        throw "Required development tooling is missing."
    }

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

    Write-Section "Required Phase 2 files"
    foreach ($RelativePath in @(
        "Cargo.toml",
        "Cargo.lock",
        "crates/dfstl-core/src/target.rs",
        "apps/dfstl-cli/src/main.rs",
        "docs/PHASE_2_TARGET_DISCOVERY.md",
        "docs/TARGET_IDENTIFICATION_SCHEMA.md",
        "scripts/run-phase2-tests.ps1"
    )) {
        Assert-True $RelativePath (Test-Path -LiteralPath (Join-Path $RepoRoot $RelativePath) -PathType Leaf)
    }

    Invoke-LoggedCommand "Cargo metadata" "cargo" @("metadata", "--format-version", "1", "--no-deps") | Out-Null
    Invoke-LoggedCommand "Formatting" "cargo" @("fmt", "--all", "--check") | Out-Null
    Invoke-LoggedCommand "Strict Clippy" "cargo" @("clippy", "--workspace", "--all-targets", "--", "-D", "warnings") | Out-Null
    Invoke-LoggedCommand "Debug tests" "cargo" @("test", "--workspace", "--", "--nocapture") | Out-Null
    if ($Release) {
        Invoke-LoggedCommand "Release tests" "cargo" @("test", "--workspace", "--release", "--", "--nocapture") | Out-Null
    }

    Write-Section "CLI Phase 2 model"
    $Describe = Capture-NativeOutput "cargo" @("run", "-p", "dfstl-cli", "--", "describe")
    Write-Log $Describe.Output
    Write-Log ("Exit code: {0}" -f $Describe.ExitCode)
    Assert-True "describe exits successfully" ($Describe.ExitCode -eq 0)
    Assert-Match "Phase marker is 2" $Describe.Output "phase:\s*2"
    Assert-Match "Target discovery advertised" $Describe.Output "target-discovery:\s*available"
    Assert-Match "SHA-256 build identification advertised" $Describe.Output "target-build-identification:\s*sha256"
    Assert-Match "Current package contract has 11 executables" $Describe.Output "expected-suite-executables:\s*11"
    Assert-Match "No active attack implementations" $Describe.Output "active-attack-implementations:\s*none"

    Write-Section "Registered Safe tests"
    $List = Capture-NativeOutput "cargo" @("run", "-p", "dfstl-cli", "--", "list")
    Write-Log $List.Output
    Write-Log ("Exit code: {0}" -f $List.ExitCode)
    Assert-True "list exits successfully" ($List.ExitCode -eq 0)
    Assert-Match "Phase 2 target self-check is registered" $List.Output "STATIC-TARGET-001"

    if (Test-Path -LiteralPath $RunRoot) {
        Remove-Item -LiteralPath $RunRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $FixtureRoot | Out-Null

    Write-Section "Complete target identification"
    $CompleteTarget = Join-Path $FixtureRoot "complete-target"
    New-SyntheticTarget -Path $CompleteTarget -WithMetadata -WithManifest

    $Inspect = Capture-NativeOutput "cargo" @(
        "run", "-p", "dfstl-cli", "--", "target", "inspect",
        "--target", $CompleteTarget, "--json"
    )
    Write-Log $Inspect.Output
    Write-Log ("Exit code: {0}" -f $Inspect.ExitCode)
    Assert-True "complete target inspection exits successfully" ($Inspect.ExitCode -eq 0)

    try {
        $TargetReport = $Inspect.Output | ConvertFrom-Json
        Assert-True "target is complete" ($TargetReport.complete -eq $true)
        Assert-True "all 11 executables identified" ($TargetReport.executables.Count -eq 11)
        Assert-True "manifest validates" ($TargetReport.manifest_status -eq "valid")
        Assert-True "version metadata parsed" ($TargetReport.build_info.version -eq "v9.9.9-dfstl")
        Assert-True "commit metadata parsed" ($TargetReport.build_info.git_commit -eq "0123456789abcdef0123456789abcdef01234567")
        Assert-True "build fingerprint is SHA-256 length" ($TargetReport.build_fingerprint -match '^[0-9a-f]{64}$')

        $AgentRecord = $TargetReport.executables | Where-Object { $_.name -eq "dragonforge-agent.exe" }
        $ExpectedAgentHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $CompleteTarget "dragonforge-agent.exe")).Hash.ToLowerInvariant()
        Assert-True "agent SHA-256 matches independent PowerShell hash" ($AgentRecord.sha256 -eq $ExpectedAgentHash)
    }
    catch {
        Write-Log ("FAIL  target JSON parsing failed: {0}" -f $_.Exception.Message)
        $Failures.Add("complete target JSON report could not be validated")
    }

    Write-Section "Single-child resolution"
    $SingleParent = Join-Path $FixtureRoot "single-parent"
    $SingleChild = Join-Path $SingleParent "DragonForge-Security-Suite-v9.9.9-dfstl-win-x64"
    New-SyntheticTarget -Path $SingleChild -WithMetadata -WithManifest
    $Single = Capture-NativeOutput "cargo" @(
        "run", "-p", "dfstl-cli", "--", "target", "inspect",
        "--target", $SingleParent, "--json"
    )
    Write-Log $Single.Output
    Write-Log ("Exit code: {0}" -f $Single.ExitCode)
    Assert-True "single child target resolves automatically" ($Single.ExitCode -eq 0)

    Write-Section "Incomplete package fails identification"
    $IncompleteTarget = Join-Path $FixtureRoot "incomplete-target"
    New-SyntheticTarget -Path $IncompleteTarget -WithMetadata -WithManifest
    Remove-Item -LiteralPath (Join-Path $IncompleteTarget "dragonforge-agent.exe") -Force
    $Incomplete = Capture-NativeOutput "cargo" @(
        "run", "-p", "dfstl-cli", "--", "target", "inspect",
        "--target", $IncompleteTarget, "--json"
    )
    Write-Log $Incomplete.Output
    Write-Log ("Exit code: {0}" -f $Incomplete.ExitCode)
    Assert-True "incomplete package exits with target failure" ($Incomplete.ExitCode -eq 1)
    try {
        $IncompleteReport = $Incomplete.Output | ConvertFrom-Json
        Assert-True "incomplete report marks complete false" ($IncompleteReport.complete -eq $false)
        Assert-True "missing Agent is reported" ($IncompleteReport.missing_executables -contains "dragonforge-agent.exe")
    }
    catch {
        $Failures.Add("incomplete target JSON report could not be validated")
    }

    Write-Section "Ambiguous target selection fails closed"
    $AmbiguousParent = Join-Path $FixtureRoot "ambiguous-parent"
    New-SyntheticTarget -Path (Join-Path $AmbiguousParent "build-a") -WithMetadata -WithManifest
    New-SyntheticTarget -Path (Join-Path $AmbiguousParent "build-b") -WithMetadata -WithManifest
    $Ambiguous = Capture-NativeOutput "cargo" @(
        "run", "-p", "dfstl-cli", "--", "target", "inspect",
        "--target", $AmbiguousParent, "--json"
    )
    Write-Log $Ambiguous.Output
    Write-Log ("Exit code: {0}" -f $Ambiguous.ExitCode)
    Assert-True "ambiguous target exits with selection failure" ($Ambiguous.ExitCode -eq 4)
    Assert-Match "ambiguous target refusal is explicit" $Ambiguous.Output "ambiguous DragonForge target"

    Write-Section "Safe runner regression"
    $EvidenceRoot = Join-Path $RunRoot "runner-evidence"
    $Run = Capture-NativeOutput "cargo" @("run", "-p", "dfstl-cli", "--", "run", "--output", $EvidenceRoot)
    Write-Log $Run.Output
    Write-Log ("Exit code: {0}" -f $Run.ExitCode)
    Assert-True "Safe runner still exits successfully" ($Run.ExitCode -eq 0)
    Assert-Match "Target discovery self-check passes in runner" $Run.Output "STATIC-TARGET-001\s+pass"

    Invoke-LoggedCommand "Release build" "cargo" @("build", "--workspace", "--release") | Out-Null

    Write-Section "Final result"
    Write-Log ("Finished:     {0}" -f (Get-Date).ToString("o"))
    Write-Log ("Commit:       {0}" -f $Commit)
    Write-Log ("Warnings:     {0}" -f $Warnings.Count)
    Write-Log ("Failures:     {0}" -f $Failures.Count)

    if ($Warnings.Count -gt 0) {
        Write-Log ""
        Write-Log "Warnings:"
        foreach ($Warning in $Warnings) {
            Write-Log ("  - {0}" -f $Warning)
        }
    }

    if ($Failures.Count -gt 0) {
        Write-Log ""
        Write-Log "Failures:"
        foreach ($Failure in $Failures) {
            Write-Log ("  - {0}" -f $Failure)
        }
        Write-Log ""
        Write-Log "PHASE 2 VALIDATION: FAIL"
    }
    else {
        Write-Log ""
        Write-Log "PHASE 2 VALIDATION: PASS"
    }
}
catch {
    Write-Section "Validation script failure"
    Write-Log ("ERROR: {0}" -f $_.Exception.Message)
    $Failures.Add($_.Exception.Message)
    Write-Log ""
    Write-Log "PHASE 2 VALIDATION: FAIL"
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

if ($Failures.Count -gt 0) {
    exit 1
}
exit 0
