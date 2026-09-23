param([switch]$Release)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$LogDir = Join-Path $RepoRoot "test-logs"
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogPath = Join-Path $LogDir "phase6-validation-$Timestamp.log"
$HashPath = "$LogPath.sha256"
$RunRoot = Join-Path $RepoRoot "results\phase6-validation-$Timestamp"
$LabRoot = Join-Path $RunRoot "filesystem-lab"
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
    if ($Result.ExitCode -ne 0) {
        $Failures.Add("$Name failed with exit code $($Result.ExitCode)")
    }
    $Result
}

function Validate-Manifest {
    param([string]$Root)
    $Manifest = Join-Path $Root "SHA256SUMS"
    Assert-True "filesystem lab SHA256SUMS exists" (Test-Path -LiteralPath $Manifest -PathType Leaf)
    if (-not (Test-Path -LiteralPath $Manifest -PathType Leaf)) { return }

    foreach ($Line in Get-Content -LiteralPath $Manifest) {
        if ([string]::IsNullOrWhiteSpace($Line)) { continue }
        $Parts = $Line -split '  ', 2
        Assert-True "manifest line has hash and path" ($Parts.Count -eq 2)
        if ($Parts.Count -ne 2) { continue }
        $Relative = $Parts[1].Replace('/', [IO.Path]::DirectorySeparatorChar)
        $Target = Join-Path $Root $Relative
        Assert-True "manifest target exists: $($Parts[1])" (Test-Path -LiteralPath $Target -PathType Leaf)
        if (Test-Path -LiteralPath $Target -PathType Leaf) {
            $Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Target).Hash.ToLowerInvariant()
            Assert-True "manifest hash matches: $($Parts[1])" ($Actual -eq $Parts[0].ToLowerInvariant())
        }
    }
}

Push-Location $RepoRoot
try {
    Write-Section "DragonForge Security Test Lab - Phase 6 Validation"
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

    Write-Section "Required Phase 6 files"
    foreach ($RelativePath in @(
        "crates/dfstl-core/src/filesystem_lab.rs",
        "apps/dfstl-cli/src/main.rs",
        "docs/PHASE_6_FILESYSTEM_LAB.md",
        "docs/FILESYSTEM_LAB_SCHEMA.md",
        "scripts/run-phase6-tests.ps1"
    )) {
        Assert-True $RelativePath (Test-Path -LiteralPath (Join-Path $RepoRoot $RelativePath) -PathType Leaf)
    }

    Invoke-LoggedCommand "Cargo metadata" "cargo" @("metadata", "--format-version", "1", "--no-deps") | Out-Null
    Invoke-LoggedCommand "Formatting" "cargo" @("fmt", "--all", "--check") | Out-Null
    Invoke-LoggedCommand "Strict Clippy" "cargo" @("clippy", "--workspace", "--all-targets", "--", "-D", "warnings") | Out-Null
    Invoke-LoggedCommand "Debug tests" "cargo" @("test", "--workspace", "--", "--nocapture") | Out-Null
    Invoke-LoggedCommand "Filesystem lab regression" "cargo" @(
        "test", "-p", "dfstl-core", "disposable_lab_exercises_containment_and_races", "--", "--nocapture"
    ) | Out-Null
    Invoke-LoggedCommand "Path policy regression" "cargo" @(
        "test", "-p", "dfstl-core", "deterministic_path_corpus_matches_expected_policy", "--", "--nocapture"
    ) | Out-Null
    if ($Release) {
        Invoke-LoggedCommand "Release tests" "cargo" @("test", "--workspace", "--release", "--", "--nocapture") | Out-Null
    }

    Invoke-LoggedCommand "Debug CLI build" "cargo" @("build", "-p", "dfstl-cli") | Out-Null
    $CliPath = Join-Path $RepoRoot "target\debug\dfstl-cli.exe"
    Assert-True "debug DFSTL CLI exists" (Test-Path -LiteralPath $CliPath -PathType Leaf)

    Write-Section "CLI Phase 6 model"
    $Describe = Capture-NativeOutput $CliPath @("describe")
    Write-Log $Describe.Output
    Write-Log ("Exit code: {0}" -f $Describe.ExitCode)
    Assert-True "describe exits successfully" ($Describe.ExitCode -eq 0)
    Assert-Match "Phase marker is 6" $Describe.Output "phase:\s*6"
    Assert-Match "Filesystem lab advertised" $Describe.Output "filesystem-lab:\s*available"
    Assert-Match "Filesystem lab is LabOnly" $Describe.Output "filesystem-lab-safety-class:\s*lab-only"
    Assert-Match "Reparse testing advertised" $Describe.Output "windows-reparse-testing:\s*available"
    Assert-Match "TOCTOU lab is disposable-only" $Describe.Output "toctou-race-testing:\s*disposable-only"

    Write-Section "Registered tests and safety"
    $List = Capture-NativeOutput $CliPath @("list")
    Write-Log $List.Output
    Write-Log ("Exit code: {0}" -f $List.ExitCode)
    Assert-True "list exits successfully" ($List.ExitCode -eq 0)
    Assert-Match "Phase 6 filesystem test registered" $List.Output "FS-LAB-001\s+lab-only\s+FS"

    Write-Section "Path policy corpus"
    $PathCorpusResult = Capture-NativeOutput $CliPath @("filesystem", "path-corpus")
    Write-Log $PathCorpusResult.Output
    Write-Log ("Exit code: {0}" -f $PathCorpusResult.ExitCode)
    Assert-True "path corpus exits successfully" ($PathCorpusResult.ExitCode -eq 0)
    try {
        $PathCorpus = $PathCorpusResult.Output | ConvertFrom-Json
        Assert-True "path corpus schema_version is 1" ($PathCorpus.schema_version -eq 1)
        Assert-True "path corpus reports all_expected" ([bool]$PathCorpus.all_expected)
        Assert-True "path corpus has 22 cases" ($PathCorpus.cases.Count -eq 22)
        foreach ($Id in @("dotdot", "drive-prefix", "unc-prefix", "alternate-stream", "nul", "con-extension", "trailing-dot", "decomposed-unicode")) {
            Assert-True "path corpus includes $Id" (@($PathCorpus.cases | Where-Object { $_.id -eq $Id }).Count -eq 1)
        }
    }
    catch {
        Write-Log ("FAIL  path corpus JSON parsing failed: {0}" -f $_.Exception.Message)
        $Failures.Add("path corpus JSON validation")
    }

    if (Test-Path -LiteralPath $RunRoot) { Remove-Item -LiteralPath $RunRoot -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $RunRoot | Out-Null

    Write-Section "LabOnly authorization gate"
    $Denied = Capture-NativeOutput $CliPath @("filesystem", "lab", "--root", $LabRoot)
    Write-Log $Denied.Output
    Write-Log ("Exit code: {0}" -f $Denied.ExitCode)
    Assert-True "filesystem lab without --lab-ack is refused" ($Denied.ExitCode -eq 7)
    Assert-True "refused lab creates no root" (-not (Test-Path -LiteralPath $LabRoot))

    Write-Section "Disposable filesystem lab"
    $Lab = Capture-NativeOutput $CliPath @(
        "filesystem", "lab",
        "--root", $LabRoot,
        "--lab-ack",
        "--json"
    )
    Write-Log $Lab.Output
    Write-Log ("Exit code: {0}" -f $Lab.ExitCode)
    Assert-True "filesystem lab exits successfully" ($Lab.ExitCode -eq 0)
    try {
        $LabReport = $Lab.Output | ConvertFrom-Json
        Assert-True "filesystem lab schema_version is 1" ($LabReport.schema_version -eq 1)
        Assert-True "filesystem lab has no failures" (-not [bool]$LabReport.has_failures)
        foreach ($Id in @(
            "path-policy-corpus",
            "restore-containment",
            "destination-create-new-race",
            "hard-link-alias",
            "source-replacement-race"
        )) {
            $Case = @($LabReport.cases | Where-Object { $_.id -eq $Id })
            Assert-True "filesystem lab includes $Id" ($Case.Count -eq 1)
            if ($Case.Count -eq 1) {
                Assert-True "$Id passes" ($Case[0].status -eq "pass")
            }
        }

        $ReparseCases = @($LabReport.cases | Where-Object { $_.id -match "reparse" })
        Assert-True "filesystem lab reports reparse capability" ($ReparseCases.Count -ge 1)
        foreach ($Case in $ReparseCases) {
            Assert-True "$($Case.id) is pass or skipped" ($Case.status -in @("pass", "skipped"))
        }
    }
    catch {
        Write-Log ("FAIL  filesystem lab JSON parsing failed: {0}" -f $_.Exception.Message)
        $Failures.Add("filesystem lab JSON validation")
    }

    Assert-True "filesystem-lab.json exists" (Test-Path -LiteralPath (Join-Path $LabRoot "filesystem-lab.json") -PathType Leaf)
    Assert-True "filesystem-lab.txt exists" (Test-Path -LiteralPath (Join-Path $LabRoot "filesystem-lab.txt") -PathType Leaf)
    Validate-Manifest $LabRoot

    Write-Section "Safe runner enforcement"
    $SafeRun = Capture-NativeOutput $CliPath @("run", "--output", (Join-Path $RunRoot "safe-runner"))
    Write-Log $SafeRun.Output
    Write-Log ("Exit code: {0}" -f $SafeRun.ExitCode)
    Assert-True "Safe runner exits successfully" ($SafeRun.ExitCode -eq 0)
    Assert-Match "Filesystem lab skipped under Safe policy" $SafeRun.Output "FS-LAB-001\s+skipped"

    Write-Section "Controlled runner enforcement"
    $ControlledRun = Capture-NativeOutput $CliPath @(
        "run", "--controlled", "--output", (Join-Path $RunRoot "controlled-runner")
    )
    Write-Log $ControlledRun.Output
    Write-Log ("Exit code: {0}" -f $ControlledRun.ExitCode)
    Assert-True "Controlled runner exits successfully" ($ControlledRun.ExitCode -eq 0)
    Assert-Match "Filesystem lab skipped under Controlled policy" $ControlledRun.Output "FS-LAB-001\s+skipped"

    Write-Section "LabOnly runner enforcement"
    $LabRun = Capture-NativeOutput $CliPath @(
        "run", "--lab-ack", "--output", (Join-Path $RunRoot "lab-runner")
    )
    Write-Log $LabRun.Output
    Write-Log ("Exit code: {0}" -f $LabRun.ExitCode)
    Assert-True "LabOnly runner exits successfully" ($LabRun.ExitCode -eq 0)
    Assert-Match "Filesystem lab self-check passes" $LabRun.Output "FS-LAB-001\s+pass"

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
        Write-Log "PHASE 6 VALIDATION: FAIL"
    }
    else {
        Write-Log ""
        Write-Log "PHASE 6 VALIDATION: PASS"
    }
}
catch {
    Write-Section "Validation script failure"
    Write-Log ("ERROR: {0}" -f $_.Exception.Message)
    $Failures.Add($_.Exception.Message)
    Write-Log ""
    Write-Log "PHASE 6 VALIDATION: FAIL"
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
