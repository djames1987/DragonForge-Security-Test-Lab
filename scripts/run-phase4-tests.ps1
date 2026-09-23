param(
    [switch]$Release
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$LogDir = Join-Path $RepoRoot "test-logs"
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogPath = Join-Path $LogDir "phase4-validation-$Timestamp.log"
$HashPath = "$LogPath.sha256"
$RunRoot = Join-Path $RepoRoot "results\phase4-validation-$Timestamp"
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

function Add-Bytes {
    param(
        [System.Collections.Generic.List[byte]]$List,
        [byte[]]$Bytes
    )
    foreach ($Byte in $Bytes) {
        $List.Add($Byte)
    }
}

function New-ArgonSeed {
    param([string]$Path, [string]$Magic)

    $Bytes = New-Object 'System.Collections.Generic.List[byte]'
    Add-Bytes $Bytes ([System.Text.Encoding]::ASCII.GetBytes($Magic))
    Add-Bytes $Bytes ([BitConverter]::GetBytes([uint16]1))
    Add-Bytes $Bytes ([BitConverter]::GetBytes([uint32]65536))
    Add-Bytes $Bytes ([BitConverter]::GetBytes([uint32]3))
    Add-Bytes $Bytes ([BitConverter]::GetBytes([uint32]1))
    Add-Bytes $Bytes ([byte[]](1..16 | ForEach-Object { 7 }))
    Add-Bytes $Bytes ([byte[]](1..12 | ForEach-Object { 9 }))
    Add-Bytes $Bytes ([byte[]](1..32 | ForEach-Object { 85 }))
    [System.IO.File]::WriteAllBytes($Path, $Bytes.ToArray())
}

function New-LengthSeed {
    param([string]$Path, [string]$Magic)

    $Cipher = [byte[]](1..32 | ForEach-Object { 102 })
    $Bytes = New-Object 'System.Collections.Generic.List[byte]'
    Add-Bytes $Bytes ([System.Text.Encoding]::ASCII.GetBytes($Magic))
    Add-Bytes $Bytes ([BitConverter]::GetBytes([uint16]1))
    Add-Bytes $Bytes ([byte[]](1..16 | ForEach-Object { 7 }))
    Add-Bytes $Bytes ([byte[]](1..12 | ForEach-Object { 9 }))
    Add-Bytes $Bytes ([BitConverter]::GetBytes([uint64]$Cipher.Length))
    Add-Bytes $Bytes $Cipher
    [System.IO.File]::WriteAllBytes($Path, $Bytes.ToArray())
}

function Validate-CorpusManifest {
    param([string]$CorpusDir)

    $ManifestPath = Join-Path $CorpusDir "SHA256SUMS"
    Assert-True "SHA256SUMS exists for $CorpusDir" (Test-Path -LiteralPath $ManifestPath -PathType Leaf)
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        return
    }

    foreach ($Line in Get-Content -LiteralPath $ManifestPath) {
        if ([string]::IsNullOrWhiteSpace($Line)) {
            continue
        }
        $Parts = $Line -split '  ', 2
        if ($Parts.Count -ne 2) {
            $Failures.Add("Malformed SHA256SUMS line in $CorpusDir")
            continue
        }
        $Expected = $Parts[0].ToUpperInvariant()
        $Relative = $Parts[1].Replace('/', [IO.Path]::DirectorySeparatorChar)
        $Target = Join-Path $CorpusDir $Relative
        Assert-True "manifest target exists: $($Parts[1])" (Test-Path -LiteralPath $Target -PathType Leaf)
        if (Test-Path -LiteralPath $Target -PathType Leaf) {
            $Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Target).Hash.ToUpperInvariant()
            Assert-True "manifest hash matches: $($Parts[1])" ($Actual -eq $Expected)
        }
    }
}

function Invoke-MutationCase {
    param(
        [string]$CliPath,
        [string]$Format,
        [string]$Seed,
        [string]$Output,
        [int]$ExpectedCases
    )

    $Before = (Get-FileHash -Algorithm SHA256 -LiteralPath $Seed).Hash.ToUpperInvariant()
    $Result = Capture-NativeOutput $CliPath @(
        "format", "mutate",
        "--format", $Format,
        "--input", $Seed,
        "--output", $Output,
        "--controlled",
        "--json"
    )
    Write-Log $Result.Output
    Write-Log ("Exit code: {0}" -f $Result.ExitCode)
    Assert-True "$Format mutation exits successfully" ($Result.ExitCode -eq 0)

    try {
        $Report = $Result.Output | ConvertFrom-Json
        Assert-True "$Format corpus schema_version is 1" ($Report.schema_version -eq 1)
        Assert-True "$Format generated expected case count" ($Report.cases.Count -eq $ExpectedCases)
        Assert-True "$Format seed SHA is recorded" ($Report.seed_sha256.Length -eq 64)
        foreach ($Case in $Report.cases) {
            $CasePath = Join-Path (Join-Path $Output "cases") $Case.file_name
            Assert-True "$Format case exists: $($Case.id)" (Test-Path -LiteralPath $CasePath -PathType Leaf)
        }
    }
    catch {
        Write-Log ("FAIL  {0} corpus JSON parsing failed: {1}" -f $Format, $_.Exception.Message)
        $Failures.Add("$Format corpus JSON validation")
    }

    $After = (Get-FileHash -Algorithm SHA256 -LiteralPath $Seed).Hash.ToUpperInvariant()
    Assert-True "$Format seed remains unchanged" ($Before -eq $After)
    Validate-CorpusManifest $Output
}

Push-Location $RepoRoot
try {
    Write-Section "DragonForge Security Test Lab - Phase 4 Validation"
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

    Write-Section "Required Phase 4 files"
    foreach ($RelativePath in @(
        "Cargo.toml",
        "Cargo.lock",
        "crates/dfstl-core/src/encrypted_formats.rs",
        "apps/dfstl-cli/src/main.rs",
        "docs/PHASE_4_ENCRYPTED_FORMATS.md",
        "docs/ENCRYPTED_MUTATION_SCHEMA.md",
        "scripts/run-phase4-tests.ps1"
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

    Write-Section "CLI Phase 4 model"
    $Describe = Capture-NativeOutput $CliPath @("describe")
    Write-Log $Describe.Output
    Write-Log ("Exit code: {0}" -f $Describe.ExitCode)
    Assert-True "describe exits successfully" ($Describe.ExitCode -eq 0)
    Assert-Match "Phase marker is 4" $Describe.Output "phase:\s*4"
    Assert-Match "Encrypted mutation advertised" $Describe.Output "encrypted-format-mutation:\s*available"
    Assert-Match "Mutation class is Controlled" $Describe.Output "mutation-safety-class:\s*controlled"
    Assert-Match "All five formats advertised" $Describe.Output "dfvault,dfbackup,dfshare,dfauth,password-manager-dfvault"

    Write-Section "Registered tests and safety"
    $List = Capture-NativeOutput $CliPath @("list")
    Write-Log $List.Output
    Write-Log ("Exit code: {0}" -f $List.ExitCode)
    Assert-True "list exits successfully" ($List.ExitCode -eq 0)
    Assert-Match "Phase 4 mutation test is registered" $List.Output "PARSER-MUTATE-001\s+controlled\s+PARSER"

    if (Test-Path -LiteralPath $RunRoot) {
        Remove-Item -LiteralPath $RunRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $FixtureRoot | Out-Null

    $FileVaultSeed = Join-Path $FixtureRoot "seed-file-vault.dfvault"
    $AuthSeed = Join-Path $FixtureRoot "seed-auth.dfauth"
    $BackupSeed = Join-Path $FixtureRoot "seed.dfbackup"
    $ShareSeed = Join-Path $FixtureRoot "seed.dfshare"
    $PmSeed = Join-Path $FixtureRoot "seed-password-manager.dfvault"
    New-ArgonSeed $FileVaultSeed "DFV1"
    New-ArgonSeed $AuthSeed "DFA1"
    New-LengthSeed $BackupSeed "DFBACKUP"
    New-LengthSeed $ShareSeed "DFSHARE!"
    [System.IO.File]::WriteAllText(
        $PmSeed,
        '{"version":1,"vault_id":"synthetic","created_at":1,"updated_at":1,"items":[]}',
        $Utf8NoBom
    )

    Write-Section "Controlled authorization gate"
    $DeniedOutput = Join-Path $RunRoot "denied-output"
    $Denied = Capture-NativeOutput $CliPath @(
        "format", "mutate",
        "--format", "dfbackup",
        "--input", $BackupSeed,
        "--output", $DeniedOutput
    )
    Write-Log $Denied.Output
    Write-Log ("Exit code: {0}" -f $Denied.ExitCode)
    Assert-True "mutation without --controlled is refused" ($Denied.ExitCode -eq 6)
    Assert-True "refused mutation creates no output" (-not (Test-Path -LiteralPath $DeniedOutput))

    Write-Section "File Vault mutation matrix"
    Invoke-MutationCase $CliPath "dfvault" $FileVaultSeed (Join-Path $RunRoot "file-vault-corpus") 18

    Write-Section "Authenticator mutation matrix"
    Invoke-MutationCase $CliPath "dfauth" $AuthSeed (Join-Path $RunRoot "auth-corpus") 18

    Write-Section "Backup mutation matrix"
    Invoke-MutationCase $CliPath "dfbackup" $BackupSeed (Join-Path $RunRoot "backup-corpus") 16

    Write-Section "Secure Share mutation matrix"
    Invoke-MutationCase $CliPath "dfshare" $ShareSeed (Join-Path $RunRoot "share-corpus") 16

    Write-Section "Password Manager mutation matrix"
    Invoke-MutationCase $CliPath "password-manager" $PmSeed (Join-Path $RunRoot "pm-corpus") 8

    Write-Section "Existing output protection"
    $ExistingOutput = Join-Path $RunRoot "existing-output"
    New-Item -ItemType Directory -Path $ExistingOutput | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $ExistingOutput "sentinel.txt"), "keep", $Utf8NoBom)
    $Existing = Capture-NativeOutput $CliPath @(
        "format", "mutate",
        "--format", "dfauth",
        "--input", $AuthSeed,
        "--output", $ExistingOutput,
        "--controlled"
    )
    Write-Log $Existing.Output
    Write-Log ("Exit code: {0}" -f $Existing.ExitCode)
    Assert-True "existing output is rejected" ($Existing.ExitCode -eq 3)
    Assert-True "existing output sentinel is preserved" ((Get-Content -LiteralPath (Join-Path $ExistingOutput "sentinel.txt") -Raw) -eq "keep")

    Write-Section "Safe runner enforcement"
    $SafeEvidence = Join-Path $RunRoot "safe-runner"
    $SafeRun = Capture-NativeOutput $CliPath @("run", "--output", $SafeEvidence)
    Write-Log $SafeRun.Output
    Write-Log ("Exit code: {0}" -f $SafeRun.ExitCode)
    Assert-True "Safe runner exits successfully" ($SafeRun.ExitCode -eq 0)
    Assert-Match "Controlled mutation test is skipped under Safe policy" $SafeRun.Output "PARSER-MUTATE-001\s+skipped"

    Write-Section "Controlled runner enforcement"
    $ControlledEvidence = Join-Path $RunRoot "controlled-runner"
    $ControlledRun = Capture-NativeOutput $CliPath @("run", "--controlled", "--output", $ControlledEvidence)
    Write-Log $ControlledRun.Output
    Write-Log ("Exit code: {0}" -f $ControlledRun.ExitCode)
    Assert-True "Controlled runner exits successfully" ($ControlledRun.ExitCode -eq 0)
    Assert-Match "Controlled mutation self-check passes" $ControlledRun.Output "PARSER-MUTATE-001\s+pass"

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
        Write-Log "PHASE 4 VALIDATION: FAIL"
    }
    else {
        Write-Log ""
        Write-Log "PHASE 4 VALIDATION: PASS"
    }
}
catch {
    Write-Section "Validation script failure"
    Write-Log ("ERROR: {0}" -f $_.Exception.Message)
    $Failures.Add($_.Exception.Message)
    Write-Log ""
    Write-Log "PHASE 4 VALIDATION: FAIL"
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
