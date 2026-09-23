param([switch]$Release)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$LogDir = Join-Path $RepoRoot "test-logs"
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogPath = Join-Path $LogDir "phase7-validation-$Timestamp.log"
$HashPath = "$LogPath.sha256"
$RunRoot = Join-Path $RepoRoot "results\phase7-validation-$Timestamp"
$CapturePath = Join-Path $RunRoot "captured-request.http"
$MutationDir = Join-Path $RunRoot "sync-api-mutations"
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
    Assert-True "sync API SHA256SUMS exists" (Test-Path -LiteralPath $Manifest -PathType Leaf)
    if (-not (Test-Path -LiteralPath $Manifest -PathType Leaf)) { return }

    foreach ($Line in Get-Content -LiteralPath $Manifest) {
        if ([string]::IsNullOrWhiteSpace($Line)) { continue }
        $Parts = $Line -split '  ', 2
        Assert-True "manifest line has hash and path" ($Parts.Count -eq 2)
        if ($Parts.Count -ne 2) { continue }

        $Target = Join-Path $Root $Parts[1]
        Assert-True "manifest target exists: $($Parts[1])" (Test-Path -LiteralPath $Target -PathType Leaf)
        if (Test-Path -LiteralPath $Target -PathType Leaf) {
            $Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Target).Hash.ToLowerInvariant()
            Assert-True "manifest hash matches: $($Parts[1])" ($Actual -eq $Parts[0].ToLowerInvariant())
        }
    }
}

Push-Location $RepoRoot
try {
    Write-Section "DragonForge Security Test Lab - Phase 7 Validation"
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

    Write-Section "Required Phase 7 files"
    foreach ($RelativePath in @(
        "crates/dfstl-core/src/sync_api.rs",
        "apps/dfstl-cli/src/main.rs",
        "docs/PHASE_7_SYNC_API_HARNESS.md",
        "docs/SYNC_API_MUTATION_SCHEMA.md",
        "scripts/run-phase7-tests.ps1"
    )) {
        Assert-True $RelativePath (Test-Path -LiteralPath (Join-Path $RepoRoot $RelativePath) -PathType Leaf)
    }

    Invoke-LoggedCommand "Cargo metadata" "cargo" @("metadata", "--format-version", "1", "--no-deps") | Out-Null
    Invoke-LoggedCommand "Formatting" "cargo" @("fmt", "--all", "--check") | Out-Null
    Invoke-LoggedCommand "Strict Clippy" "cargo" @("clippy", "--workspace", "--all-targets", "--", "-D", "warnings") | Out-Null
    Invoke-LoggedCommand "Debug tests" "cargo" @("test", "--workspace", "--", "--nocapture") | Out-Null
    Invoke-LoggedCommand "Sync API loopback regression" "cargo" @(
        "test", "-p", "dfstl-core", "loopback_probe_exercises_non_state_changing_matrix", "--", "--nocapture"
    ) | Out-Null
    Invoke-LoggedCommand "Sync request mutation regression" "cargo" @(
        "test", "-p", "dfstl-core", "offline_request_mutations_are_deterministic_and_non_destructive", "--", "--nocapture"
    ) | Out-Null
    if ($Release) {
        Invoke-LoggedCommand "Release tests" "cargo" @("test", "--workspace", "--release", "--", "--nocapture") | Out-Null
    }

    $CliPath = Join-Path $RepoRoot "target\release\dfstl-cli.exe"
    if (Test-Path -LiteralPath $CliPath -PathType Leaf) {
        Remove-Item -LiteralPath $CliPath -Force
    }
    Invoke-LoggedCommand "Fresh release CLI build" "cargo" @("build", "-p", "dfstl-cli", "--release") | Out-Null
    Assert-True "fresh release DFSTL CLI exists" (Test-Path -LiteralPath $CliPath -PathType Leaf)
    if (-not (Test-Path -LiteralPath $CliPath -PathType Leaf)) {
        throw "Fresh Phase 7 CLI build did not produce an executable; refusing stale CLI checks."
    }

    Write-Section "CLI Phase 7 model"
    $Describe = Capture-NativeOutput $CliPath @("describe")
    Write-Log $Describe.Output
    Write-Log ("Exit code: {0}" -f $Describe.ExitCode)
    Assert-True "describe exits successfully" ($Describe.ExitCode -eq 0)
    Assert-Match "Phase marker is 7" $Describe.Output "phase:\s*7"
    Assert-Match "Sync API harness advertised" $Describe.Output "password-manager-sync-api-harness:\s*available"
    Assert-Match "Sync API protocol baseline is 2" $Describe.Output "sync-api-protocol-baseline:\s*2"
    Assert-Match "Sync API live harness is Controlled" $Describe.Output "sync-api-live-safety-class:\s*controlled"
    Assert-Match "Sync API target is loopback-only" $Describe.Output "sync-api-live-target:\s*ipv4-loopback-only"
    Assert-Match "Sync request mutation is offline-only" $Describe.Output "sync-api-request-mutation:\s*offline-only"

    Write-Section "Registered tests and safety"
    $List = Capture-NativeOutput $CliPath @("list")
    Write-Log $List.Output
    Write-Log ("Exit code: {0}" -f $List.ExitCode)
    Assert-True "list exits successfully" ($List.ExitCode -eq 0)
    Assert-Match "Phase 7 sync API test registered" $List.Output "API-SYNC-001\s+controlled\s+API"

    if (Test-Path -LiteralPath $RunRoot) { Remove-Item -LiteralPath $RunRoot -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $RunRoot | Out-Null

    Write-Section "Controlled authorization gates"
    $DeniedProbe = Capture-NativeOutput $CliPath @(
        "sync-api", "probe", "--base-url", "http://127.0.0.1:8787"
    )
    Write-Log $DeniedProbe.Output
    Write-Log ("Probe exit code: {0}" -f $DeniedProbe.ExitCode)
    Assert-True "sync API probe without --controlled is refused" ($DeniedProbe.ExitCode -eq 6)

    $DeniedMutate = Capture-NativeOutput $CliPath @(
        "sync-api", "mutate", "--input", $CapturePath, "--output", $MutationDir
    )
    Write-Log $DeniedMutate.Output
    Write-Log ("Mutation exit code: {0}" -f $DeniedMutate.ExitCode)
    Assert-True "sync API mutation without --controlled is refused" ($DeniedMutate.ExitCode -eq 6)

    Write-Section "Non-loopback refusal"
    $Remote = Capture-NativeOutput $CliPath @(
        "sync-api", "probe",
        "--base-url", "http://192.0.2.1:8787",
        "--controlled"
    )
    Write-Log $Remote.Output
    Write-Log ("Exit code: {0}" -f $Remote.ExitCode)
    Assert-True "live probe refuses non-loopback target" ($Remote.ExitCode -eq 3)
    Assert-Match "non-loopback refusal is explicit" $Remote.Output "only permits IPv4 loopback"

    Write-Section "Synthetic captured request"
    $CaptureLines = @(
        "PUT /v1/vaults/00000000-0000-0000-0000-000000000001 HTTP/1.1",
        "Host: 127.0.0.1:8787",
        "Authorization: Bearer 1111111111111111111111111111111111111111111111111111111111111111",
        "X-DragonForge-Device-Id: 00000000-0000-0000-0000-000000000002",
        "X-DragonForge-Device-Timestamp: 1000",
        "X-DragonForge-Device-Signature: aabb",
        "X-DragonForge-Base-Revision: 7",
        "Content-Type: application/octet-stream",
        "Content-Length: 4",
        "",
        "test"
    )
    $Capture = [string]::Join([string][char]13 + [char]10, $CaptureLines)
    [System.IO.File]::WriteAllText($CapturePath, $Capture, $Utf8NoBom)
    $CaptureBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath $CapturePath).Hash

    Write-Section "Offline sync request mutation corpus"
    $Mutation = Capture-NativeOutput $CliPath @(
        "sync-api", "mutate",
        "--input", $CapturePath,
        "--output", $MutationDir,
        "--controlled",
        "--json"
    )
    Write-Log $Mutation.Output
    Write-Log ("Exit code: {0}" -f $Mutation.ExitCode)
    Assert-True "sync API mutation exits successfully" ($Mutation.ExitCode -eq 0)
    try {
        $Corpus = $Mutation.Output | ConvertFrom-Json
        Assert-True "sync mutation schema_version is 1" ($Corpus.schema_version -eq 1)
        Assert-True "sync mutation has 12 cases" ($Corpus.cases.Count -eq 12)
        foreach ($Id in @(
            "exact-replay",
            "missing-bearer",
            "wrong-bearer",
            "device-id-swap",
            "stale-device-timestamp",
            "invalid-device-signature",
            "base-revision-zero",
            "body-bitflip",
            "body-truncate",
            "enrollment-invalid-proof",
            "recovery-invalid-or-replayed-nonce",
            "recovery-malformed-json"
        )) {
            Assert-True "sync mutation includes $Id" (@($Corpus.cases | Where-Object { $_.id -eq $Id }).Count -eq 1)
        }
    }
    catch {
        Write-Log ("FAIL  sync mutation JSON parsing failed: {0}" -f $_.Exception.Message)
        $Failures.Add("sync mutation JSON validation")
    }

    $CaptureAfter = (Get-FileHash -Algorithm SHA256 -LiteralPath $CapturePath).Hash
    Assert-True "source capture remains unchanged" ($CaptureBefore -eq $CaptureAfter)
    Assert-True "sync-api-mutations.json exists" (Test-Path -LiteralPath (Join-Path $MutationDir "sync-api-mutations.json") -PathType Leaf)
    Validate-Manifest $MutationDir

    Write-Section "Safe runner enforcement"
    $SafeRun = Capture-NativeOutput $CliPath @("run", "--output", (Join-Path $RunRoot "safe-runner"))
    Write-Log $SafeRun.Output
    Write-Log ("Exit code: {0}" -f $SafeRun.ExitCode)
    Assert-True "Safe runner exits successfully" ($SafeRun.ExitCode -eq 0)
    Assert-Match "Sync API harness skipped under Safe policy" $SafeRun.Output "API-SYNC-001\s+skipped"

    Write-Section "Controlled runner enforcement"
    $ControlledRun = Capture-NativeOutput $CliPath @(
        "run", "--controlled", "--output", (Join-Path $RunRoot "controlled-runner")
    )
    Write-Log $ControlledRun.Output
    Write-Log ("Exit code: {0}" -f $ControlledRun.ExitCode)
    Assert-True "Controlled runner exits successfully" ($ControlledRun.ExitCode -eq 0)
    Assert-Match "Sync API harness self-check passes" $ControlledRun.Output "API-SYNC-001\s+pass"
    Assert-Match "Filesystem LabOnly test remains skipped" $ControlledRun.Output "FS-LAB-001\s+skipped"

    Write-Section "LabOnly runner regression"
    $LabRun = Capture-NativeOutput $CliPath @(
        "run", "--lab-ack", "--output", (Join-Path $RunRoot "lab-runner")
    )
    Write-Log $LabRun.Output
    Write-Log ("Exit code: {0}" -f $LabRun.ExitCode)
    Assert-True "LabOnly runner exits successfully" ($LabRun.ExitCode -eq 0)
    Assert-Match "Sync API harness passes under LabOnly policy" $LabRun.Output "API-SYNC-001\s+pass"
    Assert-Match "Filesystem LabOnly self-check still passes" $LabRun.Output "FS-LAB-001\s+pass"

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
        Write-Log "PHASE 7 VALIDATION: FAIL"
    }
    else {
        Write-Log ""
        Write-Log "PHASE 7 VALIDATION: PASS"
    }
}
catch {
    Write-Section "Validation script failure"
    Write-Log ("ERROR: {0}" -f $_.Exception.Message)
    $Failures.Add($_.Exception.Message)
    Write-Log ""
    Write-Log "PHASE 7 VALIDATION: FAIL"
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
