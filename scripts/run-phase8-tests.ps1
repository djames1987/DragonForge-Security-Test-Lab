param([switch]$Release)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$LogDir = Join-Path $RepoRoot "test-logs"
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogPath = Join-Path $LogDir "phase8-validation-$Stamp.log"
$HashPath = "$LogPath.sha256"
$RunRoot = Join-Path $RepoRoot "results\phase8-validation-$Stamp"
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
function Native([string]$Name, [string]$Command, [string[]]$Arguments) {
    Section $Name
    Log ("> " + $Command + " " + ($Arguments -join " "))
    $Old = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $Out = (& $Command @Arguments 2>&1 | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
        $Code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $Old }
    if ($Out) { Log $Out }
    Log ("Exit code: " + $Code)
    if ($Code -ne 0) { $Failures.Add($Name + " failed with exit code " + $Code) }
    [pscustomobject]@{ Output = $Out; ExitCode = $Code }
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
function ValidateManifest([string]$Root) {
    $Manifest = Join-Path $Root "SHA256SUMS"
    Pass "fuzz corpus SHA256SUMS exists" (Test-Path -LiteralPath $Manifest -PathType Leaf)
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
    Section "DragonForge Security Test Lab - Phase 8 Validation"
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

    Section "Required Phase 8 files"
    foreach ($Path in @(
        "crates/dfstl-core/src/fuzzing.rs",
        "docs/PHASE_8_FUZZING_REGRESSION.md",
        "docs/FUZZ_CORPUS_SCHEMA.md",
        "scripts/run-phase8-tests.ps1",
        "fuzz/Cargo.toml",
        "fuzz/fuzz_targets/encrypted_formats.rs",
        "fuzz/fuzz_targets/agent_json.rs",
        "fuzz/fuzz_targets/sync_http.rs",
        "fuzz/fuzz_targets/windows_path.rs",
        "corpus/regression/windows-path/1db796ce72aa13d4.bin",
        "corpus/regression/windows-path/1db796ce72aa13d4.json"
    )) { Pass $Path (Test-Path -LiteralPath (Join-Path $RepoRoot $Path) -PathType Leaf) }

    Native "Cargo metadata" "cargo" @("metadata","--format-version","1","--no-deps") | Out-Null
    Native "Formatting" "cargo" @("fmt","--all","--check") | Out-Null
    Native "Strict Clippy" "cargo" @("clippy","--workspace","--all-targets","--","-D","warnings") | Out-Null
    Native "Debug tests" "cargo" @("test","--workspace","--","--nocapture") | Out-Null
    Native "Deterministic fuzz corpus regression" "cargo" @("test","-p","dfstl-core","deterministic_corpus_repeats_for_same_seed","--","--nocapture") | Out-Null
    Native "Fuzz minimizer regression" "cargo" @("test","-p","dfstl-core","minimizer_preserves_oracle_and_reduces_input","--","--nocapture") | Out-Null
    Native "Regression promotion regression" "cargo" @("test","-p","dfstl-core","promotion_is_hash_named_and_refuses_overwrite","--","--nocapture") | Out-Null
    if ($Release) { Native "Release tests" "cargo" @("test","--workspace","--release","--","--nocapture") | Out-Null }

    $Cli = Join-Path $RepoRoot "target\release\dfstl-cli.exe"
    if (Test-Path -LiteralPath $Cli) { Remove-Item -LiteralPath $Cli -Force }
    Native "Fresh release CLI build" "cargo" @("build","-p","dfstl-cli","--release") | Out-Null
    Pass "fresh release DFSTL CLI exists" (Test-Path -LiteralPath $Cli -PathType Leaf)
    if (-not (Test-Path -LiteralPath $Cli -PathType Leaf)) { throw "Fresh Phase 8 CLI build missing." }

    Section "CLI Phase 8 model"
    $Describe = Capture $Cli @("describe")
    Log $Describe.Output
    Pass "describe exits successfully" ($Describe.ExitCode -eq 0)
    Pass "Phase marker is 8" ($Describe.Output -match "phase:\s*8")
    Pass "fuzz corpus advertised" ($Describe.Output -match "deterministic-fuzz-corpus:\s*available")
    Pass "regression promotion advertised" ($Describe.Output -match "fuzz-regression-promotion:\s*available")
    Pass "minimizer API advertised" ($Describe.Output -match "fuzz-minimizer-api:\s*available")
    Pass "cargo-fuzz scaffold advertised" ($Describe.Output -match "cargo-fuzz-scaffold:\s*available")

    $List = Capture $Cli @("list")
    Log $List.Output
    Pass "Phase 8 fuzz test registered" ($List.Output -match "FUZZ-CORPUS-001\s+controlled\s+FUZZ")

    if (Test-Path -LiteralPath $RunRoot) { Remove-Item -LiteralPath $RunRoot -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $RunRoot | Out-Null
    $Seed = Join-Path $RepoRoot "corpus\seeds\agent-json.json"
    $CorpusDir = Join-Path $RunRoot "agent-json-corpus"

    Section "Controlled authorization gate"
    $Denied = Capture $Cli @("fuzz","corpus","--target","agent-json","--input",$Seed,"--output",$CorpusDir)
    Log $Denied.Output
    Pass "fuzz corpus without --controlled is refused" ($Denied.ExitCode -eq 6)

    Section "Deterministic fuzz corpus CLI"
    $SeedBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath $Seed).Hash
    $Generated = Capture $Cli @("fuzz","corpus","--target","agent-json","--input",$Seed,"--output",$CorpusDir,"--controlled","--seed","42","--count","24","--json")
    Log $Generated.Output
    Pass "fuzz corpus generation exits successfully" ($Generated.ExitCode -eq 0)
    try {
        $Corpus = $Generated.Output | ConvertFrom-Json
        Pass "fuzz corpus schema_version is 1" ($Corpus.schema_version -eq 1)
        Pass "fuzz corpus target is agent-json" ($Corpus.target -eq "agent-json")
        Pass "fuzz corpus RNG seed is 42" ($Corpus.rng_seed -eq 42)
        Pass "fuzz corpus has 24 cases" ($Corpus.cases.Count -eq 24)
        foreach ($Mutation in @("empty","truncate-one","seeded-bitflip","json-version-extreme","json-length-extreme","json-concatenated-object","seeded-byte-insert")) {
            Pass ("fuzz corpus includes " + $Mutation) (@($Corpus.cases | Where-Object { $_.mutation -eq $Mutation }).Count -ge 1)
        }
    } catch { $Failures.Add("fuzz corpus JSON validation") }
    $SeedAfter = (Get-FileHash -Algorithm SHA256 -LiteralPath $Seed).Hash
    Pass "source fuzz seed remains unchanged" ($SeedBefore -eq $SeedAfter)
    ValidateManifest $CorpusDir

    Section "Regression promotion"
    $Candidate = Join-Path $RunRoot "candidate.bin"
    $RegressionRoot = Join-Path $RunRoot "regression"
    [System.IO.File]::WriteAllBytes($Candidate, [byte[]](65,66,67,0,255))
    $CandidateBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath $Candidate).Hash
    $Promote = Capture $Cli @("fuzz","promote","--target","sync-http","--input",$Candidate,"--regression-root",$RegressionRoot,"--controlled","--note","phase8 validator synthetic fixture","--json")
    Log $Promote.Output
    Pass "regression promotion exits successfully" ($Promote.ExitCode -eq 0)
    try {
        $Fixture = $Promote.Output | ConvertFrom-Json
        Pass "regression metadata schema_version is 1" ($Fixture.schema_version -eq 1)
        Pass "regression target is sync-http" ($Fixture.target -eq "sync-http")
        $PromotedPath = Join-Path (Join-Path $RegressionRoot "sync-http") $Fixture.filename
        Pass "regression fixture exists" (Test-Path -LiteralPath $PromotedPath -PathType Leaf)
    } catch { $Failures.Add("regression promotion JSON validation") }
    $Duplicate = Capture $Cli @("fuzz","promote","--target","sync-http","--input",$Candidate,"--regression-root",$RegressionRoot,"--controlled")
    Log $Duplicate.Output
    Pass "duplicate regression promotion is refused" ($Duplicate.ExitCode -eq 3)
    $CandidateAfter = (Get-FileHash -Algorithm SHA256 -LiteralPath $Candidate).Hash
    Pass "source candidate remains unchanged" ($CandidateBefore -eq $CandidateAfter)

    Section "Permanent regression and cargo-fuzz scaffold"
    $Permanent = Join-Path $RepoRoot "corpus\regression\windows-path\1db796ce72aa13d4.bin"
    $PermanentHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Permanent).Hash.ToLowerInvariant()
    Pass "permanent regression hash is correct" ($PermanentHash -eq "1db796ce72aa13d42af362173aea63b7c6cba5ba65f1ccad1898563c15fb401b")
    $Meta = Get-Content -LiteralPath (Join-Path $RepoRoot "corpus\regression\windows-path\1db796ce72aa13d4.json") -Raw | ConvertFrom-Json
    Pass "permanent regression metadata matches" ($Meta.sha256 -eq $PermanentHash -and $Meta.target -eq "windows-path")
    $FuzzCargo = Get-Content -LiteralPath (Join-Path $RepoRoot "fuzz\Cargo.toml") -Raw
    Pass "cargo-fuzz metadata present" ($FuzzCargo -match "cargo-fuzz\s*=\s*true")
    foreach ($TargetName in @("encrypted_formats","agent_json","sync_http","windows_path")) {
        Pass ("cargo-fuzz target registered: " + $TargetName) ($FuzzCargo -match ('name\s*=\s*"' + [regex]::Escape($TargetName) + '"'))
    }

    Section "Runner safety regression"
    $Safe = Capture $Cli @("run","--output",(Join-Path $RunRoot "safe"))
    Log $Safe.Output
    Pass "Safe runner succeeds" ($Safe.ExitCode -eq 0)
    Pass "fuzz test skipped under Safe" ($Safe.Output -match "FUZZ-CORPUS-001\s+skipped")
    $Controlled = Capture $Cli @("run","--controlled","--output",(Join-Path $RunRoot "controlled"))
    Log $Controlled.Output
    Pass "Controlled runner succeeds" ($Controlled.ExitCode -eq 0)
    Pass "fuzz test passes under Controlled" ($Controlled.Output -match "FUZZ-CORPUS-001\s+pass")
    Pass "LabOnly filesystem remains skipped" ($Controlled.Output -match "FS-LAB-001\s+skipped")
    $Lab = Capture $Cli @("run","--lab-ack","--output",(Join-Path $RunRoot "lab"))
    Log $Lab.Output
    Pass "LabOnly runner succeeds" ($Lab.ExitCode -eq 0)
    Pass "fuzz test passes under LabOnly" ($Lab.Output -match "FUZZ-CORPUS-001\s+pass")

    Native "Release build" "cargo" @("build","--workspace","--release") | Out-Null

    Section "Final result"
    Log ("Finished:     " + (Get-Date).ToString("o"))
    Log ("Commit:       " + $Commit)
    Log ("Warnings:     " + $Warnings.Count)
    Log ("Failures:     " + $Failures.Count)
    if ($Failures.Count -eq 0) { Log ""; Log "PHASE 8 VALIDATION: PASS" }
    else {
        Log ""
        Log "Failures:"
        foreach ($Failure in $Failures) { Log ("  - " + $Failure) }
        Log ""
        Log "PHASE 8 VALIDATION: FAIL"
    }
}
catch {
    Section "Validation script failure"
    Log ("ERROR: " + $_.Exception.Message)
    $Failures.Add($_.Exception.Message)
    Log ""
    Log "PHASE 8 VALIDATION: FAIL"
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
