param(
    [switch]$Release
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$LogDir = Join-Path $RepoRoot "test-logs"
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogPath = Join-Path $LogDir "phase3-validation-$Timestamp.log"
$HashPath = "$LogPath.sha256"
$RunRoot = Join-Path $RepoRoot "results\phase3-validation-$Timestamp"
$FixtureRoot = Join-Path $RunRoot "fixtures"
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
    return [pscustomobject]@{ Output = $Output; ExitCode = $ExitCode }
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

function New-SourceFixture {
    param(
        [string]$Path,
        [switch]$SupplyWarnings,
        [switch]$Secret
    )

    New-Item -ItemType Directory -Force -Path (Join-Path $Path ".github\workflows") | Out-Null

    $Manifest = @"
[package]
name = "fixture-app"
version = "0.1.0"
edition = "2024"
"@
    [System.IO.File]::WriteAllText((Join-Path $Path "Cargo.toml"), $Manifest, $Utf8NoBom)

    $Lock = @"
# synthetic Cargo.lock
version = 4

[[package]]
name = "alpha"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[[package]]
name = "fixture-app"
version = "0.1.0"
"@
    [System.IO.File]::WriteAllText((Join-Path $Path "Cargo.lock"), $Lock, $Utf8NoBom)

    if ($SupplyWarnings) {
        $Workflow = @"
permissions:
  contents: read
jobs:
  test:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
"@
    }
    else {
        $Workflow = @"
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
"@
    }
    [System.IO.File]::WriteAllText((Join-Path $Path ".github\workflows\ci.yml"), $Workflow, $Utf8NoBom)

    if ($Secret) {
        $FakeSecret = "github_pat_" + ("A" * 48)
        [System.IO.File]::WriteAllText((Join-Path $Path "fixture-secret.txt"), $FakeSecret, $Utf8NoBom)
    }
    else {
        [System.IO.File]::WriteAllText((Join-Path $Path "README.md"), "synthetic fixture only", $Utf8NoBom)
    }
}

Push-Location $RepoRoot
try {
    Write-Section "DragonForge Security Test Lab - Phase 3 Validation"
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

    Write-Section "Required Phase 3 files"
    foreach ($RelativePath in @(
        "Cargo.toml",
        "Cargo.lock",
        "crates/dfstl-core/src/static_scan.rs",
        "apps/dfstl-cli/src/main.rs",
        "docs/PHASE_3_STATIC_SUPPLY_CHAIN.md",
        "docs/STATIC_SCAN_SCHEMA.md",
        "scripts/run-phase3-tests.ps1"
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

    Invoke-LoggedCommand "Debug CLI build" "cargo" @("build", "-p", "dfstl-cli") | Out-Null
    $CliPath = Join-Path $RepoRoot "target\debug\dfstl-cli.exe"
    Assert-True "debug DFSTL CLI exists" (Test-Path -LiteralPath $CliPath -PathType Leaf)

    Write-Section "CLI Phase 3 model"
    $Describe = Capture-NativeOutput $CliPath @("describe")
    Write-Log $Describe.Output
    Write-Log ("Exit code: {0}" -f $Describe.ExitCode)
    Assert-True "describe exits successfully" ($Describe.ExitCode -eq 0)
    Assert-Match "Phase marker is 3" $Describe.Output "phase:\s*3"
    Assert-Match "Static source scan advertised" $Describe.Output "static-source-scan:\s*available"
    Assert-Match "Dependency inventory advertised" $Describe.Output "dependency-inventory:\s*available"
    Assert-Match "SPDX SBOM advertised" $Describe.Output "spdx-sbom:\s*available"
    Assert-Match "External integrations advertised" $Describe.Output "external-scanners:\s*cargo-audit,cargo-deny,gitleaks"

    Write-Section "Registered Safe tests"
    $List = Capture-NativeOutput $CliPath @("list")
    Write-Log $List.Output
    Write-Log ("Exit code: {0}" -f $List.ExitCode)
    Assert-True "list exits successfully" ($List.ExitCode -eq 0)
    Assert-Match "Phase 3 supply-chain self-check is registered" $List.Output "STATIC-SUPPLY-001"

    if (Test-Path -LiteralPath $RunRoot) {
        Remove-Item -LiteralPath $RunRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $FixtureRoot | Out-Null

    Write-Section "Clean source scan"
    $CleanSource = Join-Path $FixtureRoot "clean-source"
    $CleanOutput = Join-Path $RunRoot "clean-output"
    New-SourceFixture -Path $CleanSource
    $Clean = Capture-NativeOutput $CliPath @(
        "source", "scan", "--source", $CleanSource, "--output", $CleanOutput, "--json"
    )
    Write-Log $Clean.Output
    Write-Log ("Exit code: {0}" -f $Clean.ExitCode)
    Assert-True "clean source scan exits successfully" ($Clean.ExitCode -eq 0)

    try {
        $Report = $Clean.Output | ConvertFrom-Json
        Assert-True "static scan schema_version is 1" ($Report.schema_version -eq 1)
        Assert-True "clean fixture has zero high findings" ($Report.counts.high_findings -eq 0)
        Assert-True "clean fixture has zero supply-chain findings" ($Report.counts.supply_chain_findings -eq 0)
        Assert-True "clean fixture has two Cargo.lock records" ($Report.dependency_count -eq 2)
        Assert-True "source fingerprint is SHA-256 length" ($Report.source_fingerprint -match '^[0-9a-f]{64}$')
    }
    catch {
        Write-Log ("FAIL  clean scan JSON parsing failed: {0}" -f $_.Exception.Message)
        $Failures.Add("clean static scan JSON validation")
    }

    foreach ($Artifact in @("static-scan.json", "static-scan.txt", "dependency-inventory.json", "sbom.spdx.json")) {
        Assert-True "$Artifact exists" (Test-Path -LiteralPath (Join-Path $CleanOutput $Artifact) -PathType Leaf)
    }

    try {
        $Inventory = Get-Content -LiteralPath (Join-Path $CleanOutput "dependency-inventory.json") -Raw | ConvertFrom-Json
        Assert-True "dependency inventory schema_version is 1" ($Inventory.schema_version -eq 1)
        Assert-True "dependency inventory has two records" ($Inventory.dependencies.Count -eq 2)

        $Sbom = Get-Content -LiteralPath (Join-Path $CleanOutput "sbom.spdx.json") -Raw | ConvertFrom-Json
        Assert-True "SBOM is SPDX 2.3" ($Sbom.spdxVersion -eq "SPDX-2.3")
        Assert-True "SBOM contains two packages" ($Sbom.packages.Count -eq 2)
    }
    catch {
        Write-Log ("FAIL  inventory/SBOM parsing failed: {0}" -f $_.Exception.Message)
        $Failures.Add("inventory or SBOM JSON validation")
    }

    Write-Section "Supply-chain warning scan"
    $SupplySource = Join-Path $FixtureRoot "supply-source"
    $SupplyOutput = Join-Path $RunRoot "supply-output"
    New-SourceFixture -Path $SupplySource -SupplyWarnings
    $Supply = Capture-NativeOutput $CliPath @(
        "source", "scan", "--source", $SupplySource, "--output", $SupplyOutput, "--json"
    )
    Write-Log $Supply.Output
    Write-Log ("Exit code: {0}" -f $Supply.ExitCode)
    Assert-True "warning-only supply scan exits successfully" ($Supply.ExitCode -eq 0)
    try {
        $SupplyReport = $Supply.Output | ConvertFrom-Json
        Assert-True "supply fixture has two warnings" ($SupplyReport.counts.warning_findings -eq 2)
        Assert-True "unpinned Action finding reported" (($SupplyReport.findings | Where-Object { $_.id -eq "SUPPLY-ACTION-UNPINNED" }).Count -eq 1)
        Assert-True "self-hosted runner finding reported" (($SupplyReport.findings | Where-Object { $_.id -eq "SUPPLY-SELF-HOSTED-RUNNER" }).Count -eq 1)
    }
    catch {
        $Failures.Add("supply warning JSON validation")
    }

    Write-Section "Synthetic secret detection"
    $SecretSource = Join-Path $FixtureRoot "secret-source"
    $SecretOutput = Join-Path $RunRoot "secret-output"
    New-SourceFixture -Path $SecretSource -Secret
    $Secret = Capture-NativeOutput $CliPath @(
        "source", "scan", "--source", $SecretSource, "--output", $SecretOutput, "--json"
    )
    Write-Log $Secret.Output
    Write-Log ("Exit code: {0}" -f $Secret.ExitCode)
    Assert-True "high-confidence secret finding exits with failure" ($Secret.ExitCode -eq 1)
    try {
        $SecretReport = $Secret.Output | ConvertFrom-Json
        Assert-True "secret fixture has one high finding" ($SecretReport.counts.high_findings -eq 1)
        Assert-True "GitHub PAT rule reported" (($SecretReport.findings | Where-Object { $_.id -eq "SECRET-GITHUB-PAT" }).Count -eq 1)
    }
    catch {
        $Failures.Add("secret finding JSON validation")
    }

    $SecretEvidence = (Get-Content -LiteralPath (Join-Path $SecretOutput "static-scan.json") -Raw) +
        (Get-Content -LiteralPath (Join-Path $SecretOutput "static-scan.txt") -Raw)
    Assert-True "secret value is redacted from evidence" ($SecretEvidence -notmatch "github_pat_A{20}")

    Write-Section "Safe runner regression"
    $EvidenceRoot = Join-Path $RunRoot "runner-evidence"
    $Run = Capture-NativeOutput $CliPath @("run", "--output", $EvidenceRoot)
    Write-Log $Run.Output
    Write-Log ("Exit code: {0}" -f $Run.ExitCode)
    Assert-True "Safe runner still exits successfully" ($Run.ExitCode -eq 0)
    Assert-Match "Static scan self-check passes in runner" $Run.Output "STATIC-SUPPLY-001\s+pass"

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
        Write-Log "PHASE 3 VALIDATION: FAIL"
    }
    else {
        Write-Log ""
        Write-Log "PHASE 3 VALIDATION: PASS"
    }
}
catch {
    Write-Section "Validation script failure"
    Write-Log ("ERROR: {0}" -f $_.Exception.Message)
    $Failures.Add($_.Exception.Message)
    Write-Log ""
    Write-Log "PHASE 3 VALIDATION: FAIL"
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
