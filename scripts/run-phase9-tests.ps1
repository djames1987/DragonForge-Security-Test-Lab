param([switch]$Release)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$LogDir = Join-Path $RepoRoot "test-logs"
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogPath = Join-Path $LogDir "phase9-validation-$Stamp.log"
$HashPath = "$LogPath.sha256"
$RunRoot = Join-Path $RepoRoot "results\phase9-validation-$Stamp"
$Sentinels = Join-Path $RepoRoot "corpus\seeds\phase9-sentinels.txt"
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
    Section "DragonForge Security Test Lab - Phase 9 Validation"
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

    Section "Required Phase 9 files"
    foreach ($Path in @(
        "crates/dfstl-core/src/secret_leak.rs",
        "docs/PHASE_9_SECRET_MEMORY.md",
        "docs/SECRET_LEAK_SCHEMA.md",
        "corpus/seeds/phase9-sentinels.txt",
        "scripts/run-phase9-tests.ps1"
    )) { Pass $Path (Test-Path -LiteralPath (Join-Path $RepoRoot $Path) -PathType Leaf) }

    Native "Cargo metadata" "cargo" @("metadata","--format-version","1","--no-deps") | Out-Null
    Native "Formatting" "cargo" @("fmt","--all","--check") | Out-Null
    Native "Strict Clippy" "cargo" @("clippy","--workspace","--all-targets","--","-D","warnings") | Out-Null
    Native "Debug tests" "cargo" @("test","--workspace","--","--nocapture") | Out-Null
    Native "Secret representation regression" "cargo" @(
        "test","-p","dfstl-core","scanner_finds_raw_hex_and_base64_without_emitting_secret_value","--","--nocapture"
    ) | Out-Null
    Native "Process dump regression" "cargo" @(
        "test","-p","dfstl-core","process_dump_scanner_detects_synthetic_marker","--","--nocapture"
    ) | Out-Null
    Native "Memory lifecycle regression" "cargo" @(
        "test","-p","dfstl-core","synthetic_memory_buffer_is_cleared_in_place","--","--nocapture"
    ) | Out-Null
    if ($Release) { Native "Release tests" "cargo" @("test","--workspace","--release","--","--nocapture") | Out-Null }

    $Cli = Join-Path $RepoRoot "target\release\dfstl-cli.exe"
    if (Test-Path -LiteralPath $Cli) { Remove-Item -LiteralPath $Cli -Force }
    Native "Fresh release CLI build" "cargo" @("build","-p","dfstl-cli","--release") | Out-Null
    Pass "fresh release DFSTL CLI exists" (Test-Path -LiteralPath $Cli -PathType Leaf)
    if (-not (Test-Path -LiteralPath $Cli -PathType Leaf)) { throw "Fresh Phase 9 CLI build missing." }

    Section "CLI Phase 9 model"
    $Describe = Capture $Cli @("describe")
    Log $Describe.Output
    Pass "describe exits successfully" ($Describe.ExitCode -eq 0)
    Pass "Phase marker is 9" ($Describe.Output -match "phase:\s*9")
    Pass "sentinel scanner advertised" ($Describe.Output -match "synthetic-secret-sentinel-scan:\s*available")
    Pass "UTF-16LE representation advertised" ($Describe.Output -match "utf16le")
    Pass "artifact scan is Controlled" ($Describe.Output -match "secret-artifact-scan-safety-class:\s*controlled")
    Pass "dump scan is LabOnly" ($Describe.Output -match "process-dump-scan-safety-class:\s*lab-only")
    Pass "memory self-check advertised" ($Describe.Output -match "memory-lifecycle-self-check:\s*available")

    $List = Capture $Cli @("list")
    Log $List.Output
    Pass "LEAK test registered" ($List.Output -match "LEAK-SENTINEL-001\s+controlled\s+LEAK")
    Pass "MEMORY test registered" ($List.Output -match "MEMORY-LIFE-001\s+lab-only\s+MEMORY")

    if (Test-Path -LiteralPath $RunRoot) { Remove-Item -LiteralPath $RunRoot -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $RunRoot | Out-Null
    $CleanRoot = Join-Path $RunRoot "clean-artifacts"
    $LeakRoot = Join-Path $RunRoot "leaky-artifacts"
    $DumpPath = Join-Path $RunRoot "synthetic.dmp"
    New-Item -ItemType Directory -Force -Path $CleanRoot,$LeakRoot | Out-Null
    [IO.File]::WriteAllText((Join-Path $CleanRoot "security-center.log"), "password=[REDACTED] token=[REDACTED]", $Utf8NoBom)
    [IO.File]::WriteAllText((Join-Path $CleanRoot "support-bundle.json"), '{"diagnostics":"sanitized"}', $Utf8NoBom)

    $RawSecret = "DFSTL-PHASE9-SYNC-TOKEN-0123456789"
    [IO.File]::WriteAllText((Join-Path $LeakRoot "unsafe.log"), ("prefix " + $RawSecret + " suffix"), $Utf8NoBom)
    [IO.File]::WriteAllBytes($DumpPath, [Text.Encoding]::Unicode.GetBytes("prefix " + $RawSecret + " suffix"))

    Section "Authorization gates"
    $Denied = Capture $Cli @("secret-leak","scan","--root",$CleanRoot,"--sentinels",$Sentinels,"--output",(Join-Path $RunRoot "denied"))
    Log $Denied.Output
    Pass "artifact scan without --controlled is refused" ($Denied.ExitCode -eq 6)
    $DeniedDump = Capture $Cli @("secret-leak","dump-scan","--dump",$DumpPath,"--sentinels",$Sentinels,"--output",(Join-Path $RunRoot "denied-dump"))
    Log $DeniedDump.Output
    Pass "dump scan without --lab-ack is refused" ($DeniedDump.ExitCode -eq 7)
    $DeniedMemory = Capture $Cli @("secret-leak","memory-check")
    Log $DeniedMemory.Output
    Pass "memory self-check without --controlled is refused" ($DeniedMemory.ExitCode -eq 6)

    Section "Clean artifact scan"
    $CleanOut = Join-Path $RunRoot "clean-evidence"
    $Clean = Capture $Cli @("secret-leak","scan","--root",$CleanRoot,"--sentinels",$Sentinels,"--output",$CleanOut,"--controlled","--json")
    Log $Clean.Output
    Pass "clean artifact scan succeeds" ($Clean.ExitCode -eq 0)
    try {
        $CleanJson = $Clean.Output | ConvertFrom-Json
        Pass "clean scan schema_version is 1" ($CleanJson.schema_version -eq 1)
        Pass "clean scan scope is artifact-tree" ($CleanJson.scope -eq "artifact-tree")
        Pass "clean scan has zero findings" ($CleanJson.findings.Count -eq 0 -and $CleanJson.clean)
    } catch { $Failures.Add("clean scan JSON validation") }
    Pass "clean scan output does not expose sentinel" (-not $Clean.Output.Contains($RawSecret))
    ValidateManifest $CleanOut

    Section "Intentional artifact leak"
    $LeakOut = Join-Path $RunRoot "leak-evidence"
    $Leak = Capture $Cli @("secret-leak","scan","--root",$LeakRoot,"--sentinels",$Sentinels,"--output",$LeakOut,"--controlled","--json")
    Log $Leak.Output
    Pass "leaky artifact scan returns finding status" ($Leak.ExitCode -eq 1)
    Pass "leaky scan reports sentinel ID" ($Leak.Output -match '"sentinel_id":"sync-token"')
    Pass "leaky scan does not echo sentinel value" (-not $Leak.Output.Contains($RawSecret))
    $LeakEvidence = Get-Content -LiteralPath (Join-Path $LeakOut "secret-leak.json") -Raw
    Pass "leak evidence does not contain sentinel value" (-not $LeakEvidence.Contains($RawSecret))
    ValidateManifest $LeakOut

    Section "Synthetic memory lifecycle"
    $Memory = Capture $Cli @("secret-leak","memory-check","--controlled")
    Log $Memory.Output
    Pass "memory lifecycle self-check succeeds" ($Memory.ExitCode -eq 0)
    Pass "memory lifecycle reports pass" ($Memory.Output -match "synthetic-memory-lifecycle:\s*pass")

    Section "LabOnly offline process dump scan"
    $DumpOut = Join-Path $RunRoot "dump-evidence"
    $Dump = Capture $Cli @("secret-leak","dump-scan","--dump",$DumpPath,"--sentinels",$Sentinels,"--output",$DumpOut,"--lab-ack","--json")
    Log $Dump.Output
    Pass "dump scan detects synthetic sentinel" ($Dump.ExitCode -eq 1)
    Pass "dump scan scope is process-dump" ($Dump.Output -match '"scope":"process-dump"')
    Pass "dump scan detects UTF-16LE representation" ($Dump.Output -match '"representation":"utf16le"')
    Pass "dump scan does not echo sentinel value" (-not $Dump.Output.Contains($RawSecret))
    Pass "evidence does not copy dump" (-not (Test-Path -LiteralPath (Join-Path $DumpOut "synthetic.dmp")))
    ValidateManifest $DumpOut

    Section "Runner safety regression"
    $Safe = Capture $Cli @("run","--output",(Join-Path $RunRoot "safe"))
    Log $Safe.Output
    Pass "Safe runner succeeds" ($Safe.ExitCode -eq 0)
    Pass "LEAK skipped under Safe" ($Safe.Output -match "LEAK-SENTINEL-001\s+skipped")
    Pass "MEMORY skipped under Safe" ($Safe.Output -match "MEMORY-LIFE-001\s+skipped")

    $Controlled = Capture $Cli @("run","--controlled","--output",(Join-Path $RunRoot "controlled"))
    Log $Controlled.Output
    Pass "Controlled runner succeeds" ($Controlled.ExitCode -eq 0)
    Pass "LEAK passes under Controlled" ($Controlled.Output -match "LEAK-SENTINEL-001\s+pass")
    Pass "MEMORY remains skipped under Controlled" ($Controlled.Output -match "MEMORY-LIFE-001\s+skipped")
    Pass "filesystem LabOnly remains skipped" ($Controlled.Output -match "FS-LAB-001\s+skipped")

    $Lab = Capture $Cli @("run","--lab-ack","--output",(Join-Path $RunRoot "lab"))
    Log $Lab.Output
    Pass "LabOnly runner succeeds" ($Lab.ExitCode -eq 0)
    Pass "LEAK passes under LabOnly" ($Lab.Output -match "LEAK-SENTINEL-001\s+pass")
    Pass "MEMORY passes under LabOnly" ($Lab.Output -match "MEMORY-LIFE-001\s+pass")
    Pass "filesystem passes under LabOnly" ($Lab.Output -match "FS-LAB-001\s+pass")

    Native "Release build" "cargo" @("build","--workspace","--release") | Out-Null

    Section "Final result"
    Log ("Finished:     " + (Get-Date).ToString("o"))
    Log ("Commit:       " + $Commit)
    Log ("Warnings:     " + $Warnings.Count)
    Log ("Failures:     " + $Failures.Count)
    if ($Failures.Count -eq 0) { Log ""; Log "PHASE 9 VALIDATION: PASS" }
    else {
        Log ""
        Log "Failures:"
        foreach ($Failure in $Failures) { Log ("  - " + $Failure) }
        Log ""
        Log "PHASE 9 VALIDATION: FAIL"
    }
}
catch {
    Section "Validation script failure"
    Log ("ERROR: " + $_.Exception.Message)
    $Failures.Add($_.Exception.Message)
    Log ""
    Log "PHASE 9 VALIDATION: FAIL"
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
