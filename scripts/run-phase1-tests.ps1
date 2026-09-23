param(
    [switch]$Release
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$LogDir = Join-Path $RepoRoot "test-logs"
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogPath = Join-Path $LogDir "phase1-validation-$Timestamp.log"
$HashPath = "$LogPath.sha256"
$RunRoot = Join-Path $RepoRoot "results\phase1-validation-$Timestamp"
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

function Invoke-LoggedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter()][string[]]$Arguments = @()
    )

    Write-Section $Name
    Write-Log ("> {0} {1}" -f $Command, ($Arguments -join " "))
    $PreviousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        & $Command @Arguments 2>&1 | ForEach-Object {
            $_.ToString() | ForEach-Object { Write-Log $_ }
        }
        $ExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $PreviousPreference
    }

    Write-Log ""
    Write-Log ("Exit code: {0}" -f $ExitCode)
    if ($ExitCode -ne 0) {
        $Failures.Add("$Name failed with exit code $ExitCode")
    }
    return $ExitCode
}

function Capture-NativeOutput {
    param(
        [string]$Command,
        [string[]]$Arguments
    )

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

function Assert-Match {
    param([string]$Label, [string]$Text, [string]$Pattern)
    if ($Text -match $Pattern) {
        Write-Log ("PASS  {0}" -f $Label)
    }
    else {
        Write-Log ("FAIL  {0}" -f $Label)
        $Failures.Add($Label)
    }
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

Push-Location $RepoRoot
try {
    Write-Section "DragonForge Security Test Lab - Phase 1 Validation"
    Write-Log ("Started:      {0}" -f (Get-Date).ToString("o"))
    Write-Log ("Repository:   {0}" -f $RepoRoot)
    Write-Log ("Log file:     {0}" -f $LogPath)
    Write-Log ("Run output:   {0}" -f $RunRoot)
    Write-Log ("PowerShell:   {0}" -f $PSVersionTable.PSVersion)
    Write-Log ("OS:           {0}" -f [System.Environment]::OSVersion.VersionString)
    Write-Log ("Release mode: {0}" -f [bool]$Release)

    Write-Section "Environment"
    foreach ($Tool in @("git", "rustc", "cargo", "rustup")) {
        $Found = Get-Command $Tool -ErrorAction SilentlyContinue
        Assert-True "$Tool available" ($null -ne $Found)
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

    Write-Section "Required Phase 1 files"
    $RequiredFiles = @(
        "Cargo.toml",
        "Cargo.lock",
        "crates/dfstl-core/src/model.rs",
        "crates/dfstl-core/src/hash.rs",
        "crates/dfstl-core/src/evidence.rs",
        "crates/dfstl-core/src/runner.rs",
        "apps/dfstl-cli/src/main.rs",
        "docs/PHASE_1_CORE_RUNNER.md",
        "docs/REPORT_SCHEMA.md"
    )
    foreach ($RelativePath in $RequiredFiles) {
        Assert-True $RelativePath (Test-Path -LiteralPath (Join-Path $RepoRoot $RelativePath) -PathType Leaf)
    }

    Invoke-LoggedCommand "Cargo metadata" "cargo" @("metadata", "--format-version", "1", "--no-deps") | Out-Null
    Invoke-LoggedCommand "Formatting" "cargo" @("fmt", "--all", "--check") | Out-Null
    Invoke-LoggedCommand "Strict Clippy" "cargo" @("clippy", "--workspace", "--all-targets", "--", "-D", "warnings") | Out-Null
    Invoke-LoggedCommand "Debug tests" "cargo" @("test", "--workspace", "--", "--nocapture") | Out-Null

    if ($Release) {
        Invoke-LoggedCommand "Release tests" "cargo" @("test", "--workspace", "--release", "--", "--nocapture") | Out-Null
    }

    Write-Section "CLI Phase 1 model"
    $Describe = Capture-NativeOutput "cargo" @("run", "-p", "dfstl-cli", "--", "describe")
    Write-Log $Describe.Output
    Write-Log ("Exit code: {0}" -f $Describe.ExitCode)
    Assert-True "describe exits successfully" ($Describe.ExitCode -eq 0)
    Assert-Match "Phase marker is 1" $Describe.Output "phase:\s*1"
    Assert-Match "Safe-only default remains enforced" $Describe.Output "default-safety-policy:\s*safe"
    Assert-Match "Core runner advertised" $Describe.Output "core-runner:\s*available"
    Assert-Match "JSON reporting advertised" $Describe.Output "structured-json-reporting:\s*available"
    Assert-Match "SHA-256 manifest advertised" $Describe.Output "sha256-evidence-manifest:\s*available"
    Assert-Match "No active attack implementations" $Describe.Output "active-attack-implementations:\s*none"

    Write-Section "Registered tests"
    $List = Capture-NativeOutput "cargo" @("run", "-p", "dfstl-cli", "--", "list")
    Write-Log $List.Output
    Write-Log ("Exit code: {0}" -f $List.ExitCode)
    Assert-True "list exits successfully" ($List.ExitCode -eq 0)
    Assert-Match "Runner self-check is registered" $List.Output "STATIC-RUNNER-001"
    Assert-Match "Policy self-check is registered" $List.Output "STATIC-POLICY-001"

    Write-Section "Core runner evidence run"
    if (Test-Path -LiteralPath $RunRoot) {
        Remove-Item -LiteralPath $RunRoot -Recurse -Force
    }
    $Run = Capture-NativeOutput "cargo" @("run", "-p", "dfstl-cli", "--", "run", "--output", $RunRoot)
    Write-Log $Run.Output
    Write-Log ("Exit code: {0}" -f $Run.ExitCode)
    Assert-True "safe core run exits successfully" ($Run.ExitCode -eq 0)

    $RunDirs = @(Get-ChildItem -LiteralPath $RunRoot -Directory -ErrorAction SilentlyContinue)
    Assert-True "exactly one finalized run directory exists" ($RunDirs.Count -eq 1)
    if ($RunDirs.Count -eq 1) {
        $EvidenceDir = $RunDirs[0].FullName
        Write-Log ("Evidence dir:  {0}" -f $EvidenceDir)

        $StagingDirs = @(Get-ChildItem -LiteralPath $RunRoot -Directory -Filter ".*.staging" -ErrorAction SilentlyContinue)
        Assert-True "no abandoned staging directory remains" ($StagingDirs.Count -eq 0)

        $JsonPath = Join-Path $EvidenceDir "report.json"
        $TextPath = Join-Path $EvidenceDir "report.txt"
        $ManifestPath = Join-Path $EvidenceDir "SHA256SUMS"
        Assert-True "report.json exists" (Test-Path -LiteralPath $JsonPath -PathType Leaf)
        Assert-True "report.txt exists" (Test-Path -LiteralPath $TextPath -PathType Leaf)
        Assert-True "SHA256SUMS exists" (Test-Path -LiteralPath $ManifestPath -PathType Leaf)

        if (Test-Path -LiteralPath $JsonPath -PathType Leaf) {
            try {
                $Report = Get-Content -LiteralPath $JsonPath -Raw | ConvertFrom-Json
                Assert-True "report schema_version is 1" ($Report.schema_version -eq 1)
                Assert-True "report contains at least two tests" ($Report.tests.Count -ge 2)
                Assert-True "report has zero target failures" ($Report.counts.fail -eq 0)
                Assert-True "report has zero infrastructure errors" ($Report.counts.infrastructure_error -eq 0)
                Assert-True "all built-in Phase 1 tests passed" ($Report.counts.pass -eq $Report.tests.Count)
            }
            catch {
                Write-Log ("FAIL  report.json parsing failed: {0}" -f $_.Exception.Message)
                $Failures.Add("report.json is not valid expected JSON")
            }
        }

        Write-Section "Independent SHA-256 manifest verification"
        if (Test-Path -LiteralPath $ManifestPath -PathType Leaf) {
            $ManifestLines = @(Get-Content -LiteralPath $ManifestPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            Assert-True "manifest has entries" ($ManifestLines.Count -gt 0)
            foreach ($Line in $ManifestLines) {
                if ($Line -notmatch '^([0-9a-fA-F]{64})  (.+)$') {
                    Write-Log ("FAIL  malformed manifest line: {0}" -f $Line)
                    $Failures.Add("Malformed SHA256SUMS line")
                    continue
                }
                $Expected = $Matches[1].ToUpperInvariant()
                $Relative = $Matches[2].Replace("/", [IO.Path]::DirectorySeparatorChar)
                $ArtifactPath = Join-Path $EvidenceDir $Relative
                if (-not (Test-Path -LiteralPath $ArtifactPath -PathType Leaf)) {
                    Write-Log ("FAIL  manifest file missing: {0}" -f $Relative)
                    $Failures.Add("Manifest references missing file: $Relative")
                    continue
                }
                $Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $ArtifactPath).Hash.ToUpperInvariant()
                Assert-True ("manifest hash matches {0}" -f $Relative) ($Expected -eq $Actual)
            }
        }
    }

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
        Write-Log "PHASE 1 VALIDATION: FAIL"
    }
    else {
        Write-Log ""
        Write-Log "PHASE 1 VALIDATION: PASS"
    }
}
catch {
    Write-Section "Validation script failure"
    Write-Log ("ERROR: {0}" -f $_.Exception.Message)
    $Failures.Add($_.Exception.Message)
    Write-Log ""
    Write-Log "PHASE 1 VALIDATION: FAIL"
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
