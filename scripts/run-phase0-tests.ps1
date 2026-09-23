param(
    [switch]$Release
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$LogDir = Join-Path $RepoRoot "test-logs"
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogPath = Join-Path $LogDir "phase0-validation-$Timestamp.log"
$HashPath = "$LogPath.sha256"
$Failures = [System.Collections.Generic.List[string]]::new()
$Warnings = [System.Collections.Generic.List[string]]::new()

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

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
        [Parameter()][string[]]$Arguments = @(),
        [switch]$AllowFailure
    )

    Write-Section $Name
    Write-Log ("> {0} {1}" -f $Command, ($Arguments -join " "))

    $PreviousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        & $Command @Arguments 2>&1 | ForEach-Object {
            $_ | Out-String -Stream | ForEach-Object { Write-Log $_ }
        }
        $ExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $PreviousPreference
    }

    Write-Log ""
    Write-Log ("Exit code: {0}" -f $ExitCode)

    if ($ExitCode -ne 0 -and -not $AllowFailure) {
        $Failures.Add("$Name failed with exit code $ExitCode")
    }

    return $ExitCode
}

function Test-RequiredFile {
    param([string]$RelativePath)
    $FullPath = Join-Path $RepoRoot $RelativePath
    if (Test-Path -LiteralPath $FullPath -PathType Leaf) {
        Write-Log ("PASS  {0}" -f $RelativePath)
        return $true
    }

    Write-Log ("FAIL  {0} (missing)" -f $RelativePath)
    $Failures.Add("Required file missing: $RelativePath")
    return $false
}

function Assert-OutputContains {
    param(
        [string]$Label,
        [string]$Text,
        [string]$Pattern
    )

    if ($Text -match $Pattern) {
        Write-Log ("PASS  {0}" -f $Label)
    }
    else {
        Write-Log ("FAIL  {0}" -f $Label)
        $Failures.Add("CLI invariant failed: $Label")
    }
}

Push-Location $RepoRoot
try {
    Write-Section "DragonForge Security Test Lab - Phase 0 Validation"
    Write-Log ("Started:      {0}" -f (Get-Date).ToString("o"))
    Write-Log ("Repository:   {0}" -f $RepoRoot)
    Write-Log ("Log file:     {0}" -f $LogPath)
    Write-Log ("PowerShell:   {0}" -f $PSVersionTable.PSVersion)
    Write-Log ("OS:           {0}" -f [System.Environment]::OSVersion.VersionString)
    Write-Log ("64-bit OS:    {0}" -f [System.Environment]::Is64BitOperatingSystem)
    Write-Log ("64-bit proc:  {0}" -f [System.Environment]::Is64BitProcess)
    Write-Log ("Release mode: {0}" -f [bool]$Release)

    Write-Section "Tooling availability"

    foreach ($Tool in @("git", "rustc", "cargo", "rustup")) {
        $Found = Get-Command $Tool -ErrorAction SilentlyContinue
        if ($null -eq $Found) {
            Write-Log ("FAIL  {0} not found in PATH" -f $Tool)
            $Failures.Add("Required tool missing: $Tool")
        }
        else {
            Write-Log ("PASS  {0}: {1}" -f $Tool, $Found.Source)
        }
    }

    if ($Failures.Count -gt 0) {
        throw "Required development tooling is missing. Install Git and the Rust toolchain, then rerun."
    }

    Invoke-LoggedCommand "Git version" "git" @("--version") | Out-Null
    Invoke-LoggedCommand "Rust compiler version" "rustc" @("--version", "--verbose") | Out-Null
    Invoke-LoggedCommand "Cargo version" "cargo" @("--version", "--verbose") | Out-Null
    Invoke-LoggedCommand "Rustup status" "rustup" @("show") | Out-Null

    Write-Section "Repository state"

    $Branch = (& git branch --show-current 2>&1 | Out-String).Trim()
    $Commit = (& git rev-parse HEAD 2>&1 | Out-String).Trim()
    $Status = (& git status --porcelain 2>&1 | Out-String).Trim()

    Write-Log ("Branch:       {0}" -f $Branch)
    Write-Log ("Commit:       {0}" -f $Commit)

    if ($Branch -ne "main") {
        Write-Log ("WARNING: validation is running on branch '{0}', not main." -f $Branch)
        $Warnings.Add("Validation was not run on main")
    }
    else {
        Write-Log "PASS  Current branch is main"
    }

    if ([string]::IsNullOrWhiteSpace($Status)) {
        Write-Log "PASS  Working tree is clean"
    }
    else {
        Write-Log "WARNING: working tree has uncommitted changes:"
        Write-Log $Status
        $Warnings.Add("Working tree was not clean")
    }

    Invoke-LoggedCommand "Recent commit history" "git" @("log", "-5", "--oneline", "--decorate") | Out-Null

    Write-Section "Required Phase 0 files"

    $RequiredFiles = @(
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "README.md",
        "SAFETY.md",
        "SECURITY.md",
        "config/lab.example.toml",
        "docs/ARCHITECTURE.md",
        "docs/THREAT_MODEL.md",
        "docs/TEST_TAXONOMY.md",
        "docs/ROADMAP.md",
        "docs/PHASE_0_FOUNDATION.md",
        "crates/dfstl-core/Cargo.toml",
        "crates/dfstl-core/src/lib.rs",
        "apps/dfstl-cli/Cargo.toml",
        "apps/dfstl-cli/src/main.rs"
    )

    foreach ($RequiredFile in $RequiredFiles) {
        Test-RequiredFile $RequiredFile | Out-Null
    }

    Write-Section "Workspace metadata"
    Invoke-LoggedCommand "Cargo metadata" "cargo" @("metadata", "--format-version", "1", "--no-deps") | Out-Null

    Write-Section "Formatting"
    Invoke-LoggedCommand "cargo fmt --all --check" "cargo" @("fmt", "--all", "--check") | Out-Null

    Write-Section "Strict Clippy"
    Invoke-LoggedCommand "cargo clippy --workspace --all-targets -- -D warnings" "cargo" @(
        "clippy", "--workspace", "--all-targets", "--", "-D", "warnings"
    ) | Out-Null

    Write-Section "Debug test suite"
    Invoke-LoggedCommand "cargo test --workspace" "cargo" @("test", "--workspace", "--", "--nocapture") | Out-Null

    if ($Release) {
        Write-Section "Release test suite"
        Invoke-LoggedCommand "cargo test --workspace --release" "cargo" @(
            "test", "--workspace", "--release", "--", "--nocapture"
        ) | Out-Null
    }

    Write-Section "CLI smoke and safety invariants"
    $PreviousPreference = $ErrorActionPreference
    try {
        # Windows PowerShell 5.1 wraps native stderr as NativeCommandError when
        # ErrorActionPreference is Stop. Cargo writes ordinary progress output
        # to stderr, so temporarily use Continue and evaluate the native exit code.
        $ErrorActionPreference = "Continue"
        $CliOutput = (& cargo run -p dfstl-cli -- describe 2>&1 | ForEach-Object {
            $_.ToString()
        }) -join [Environment]::NewLine
        $CliExit = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $PreviousPreference
    }

    Write-Log $CliOutput.TrimEnd()
    Write-Log ""
    Write-Log ("Exit code: {0}" -f $CliExit)

    if ($CliExit -ne 0) {
        $Failures.Add("DFSTL CLI smoke test failed with exit code $CliExit")
    }
    else {
        Assert-OutputContains "Phase marker is 0" $CliOutput "phase:\s*0"
        Assert-OutputContains "Default safety policy is safe" $CliOutput "default-safety-policy:\s*safe"
        Assert-OutputContains "Controlled tests disabled by default" $CliOutput "controlled-allowed-by-default:\s*false"
        Assert-OutputContains "Disruptive tests disabled by default" $CliOutput "disruptive-allowed-by-default:\s*false"
        Assert-OutputContains "Lab-only tests disabled by default" $CliOutput "lab-only-allowed-by-default:\s*false"
        Assert-OutputContains "No active attack implementations in Phase 0" $CliOutput "active-attack-implementations:\s*none"
    }

    Write-Section "Release build sanity"
    Invoke-LoggedCommand "cargo build --workspace --release" "cargo" @("build", "--workspace", "--release") | Out-Null

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
        Write-Log "PHASE 0 VALIDATION: FAIL"
    }
    else {
        Write-Log ""
        Write-Log "PHASE 0 VALIDATION: PASS"
    }
}
catch {
    Write-Section "Validation script failure"
    Write-Log ("ERROR: {0}" -f $_.Exception.Message)
    if ($Failures.Count -eq 0) {
        $Failures.Add($_.Exception.Message)
    }
    Write-Log ""
    Write-Log "PHASE 0 VALIDATION: FAIL"
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
