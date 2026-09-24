param([switch]$Release)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$LogDir = Join-Path $RepoRoot "test-logs"
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogPath = Join-Path $LogDir "phase11-validation-$Stamp.log"
$HashPath = "$LogPath.sha256"
$RunRoot = Join-Path $RepoRoot "results\phase11-validation-$Stamp"
$PublicLabRoot = "C:\Users\Public\DFSTL-Phase11-$Stamp"
$Failures = [System.Collections.Generic.List[string]]::new()
$Warnings = [System.Collections.Generic.List[string]]::new()
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$OwnerUserName = "DFSTL11O" + (Get-Random -Minimum 10000 -Maximum 99999)
$OtherUserName = "DFSTL11X" + (Get-Random -Minimum 10000 -Maximum 99999)
$OwnerUserCreated = $false
$OtherUserCreated = $false
$OwnerPassword = "Dfstl!" + ([Guid]::NewGuid().ToString("N")) + "9Aa"
$OtherPassword = "Dfstl!" + ([Guid]::NewGuid().ToString("N")) + "8Bb"
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
function Test-IsAdministrator {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
    return $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Test-PowerShellSyntax([string]$Path) {
    $Tokens = $null
    $Errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $Path,
        [ref]$Tokens,
        [ref]$Errors
    )
    return ($Errors.Count -eq 0)
}

Push-Location $RepoRoot
try {
    Section "DragonForge Security Test Lab - Phase 11 Validation"
    Log ("Started:      " + (Get-Date).ToString("o"))
    Log ("Repository:   " + $RepoRoot)
    Log ("Log file:     " + $LogPath)
    Log ("Run output:   " + $RunRoot)
    Log ("ACL lab root: " + $PublicLabRoot)
    Log ("Release mode: " + [bool]$Release)

    Section "Environment"
    Pass "Windows host" ($env:OS -eq "Windows_NT")
    Pass "elevated Administrator session" (Test-IsAdministrator)
    foreach ($Tool in @("git","rustc","cargo","rustup","powershell.exe")) {
        Pass ($Tool + " available") ($null -ne (Get-Command $Tool -ErrorAction SilentlyContinue))
    }
    Pass "LocalAccounts module available" ($null -ne (Get-Command New-LocalUser -ErrorAction SilentlyContinue))
    if ($Failures.Count -gt 0) { throw "Phase 11 requires elevated Windows development tooling." }

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

    Section "Required Phase 11 files"
    foreach ($Path in @(
        "crates/dfstl-core/src/windows_acl.rs",
        "scripts/invoke-phase11-acl-lab.ps1",
        "scripts/capture-phase11-dragonforge-acls.ps1",
        "docs/PHASE_11_WINDOWS_ACL.md",
        "docs/WINDOWS_ACL_SCHEMA.md",
        "scripts/run-phase11-tests.ps1"
    )) { Pass $Path (Test-Path -LiteralPath (Join-Path $RepoRoot $Path) -PathType Leaf) }

    Section "PowerShell syntax"
    foreach ($Script in @(
        "scripts/invoke-phase11-acl-lab.ps1",
        "scripts/capture-phase11-dragonforge-acls.ps1",
        "scripts/run-phase11-tests.ps1"
    )) {
        Pass ($Script + " parses") (Test-PowerShellSyntax (Join-Path $RepoRoot $Script))
    }

    Native "Cargo metadata" "cargo" @("metadata","--format-version","1","--no-deps") | Out-Null
    Native "Formatting" "cargo" @("fmt","--all","--check") | Out-Null
    Native "Strict Clippy" "cargo" @("clippy","--workspace","--all-targets","--","-D","warnings") | Out-Null
    Native "Debug tests" "cargo" @("test","--workspace","--","--nocapture") | Out-Null
    Native "ACL broad-write regression" "cargo" @(
        "test","-p","dfstl-core","broad_write_is_reported","--","--nocapture"
    ) | Out-Null
    Native "ACL restricted regression" "cargo" @(
        "test","-p","dfstl-core","restricted_sensitive_acl_is_clean","--","--nocapture"
    ) | Out-Null
    Native "ACL evidence regression" "cargo" @(
        "test","-p","dfstl-core","evidence_manifest_is_written","--","--nocapture"
    ) | Out-Null
    if ($Release) { Native "Release tests" "cargo" @("test","--workspace","--release","--","--nocapture") | Out-Null }

    $Cli = Join-Path $RepoRoot "target\release\dfstl-cli.exe"
    if (Test-Path -LiteralPath $Cli) { Remove-Item -LiteralPath $Cli -Force }
    Native "Fresh release CLI build" "cargo" @("build","-p","dfstl-cli","--release") | Out-Null
    Pass "fresh release DFSTL CLI exists" (Test-Path -LiteralPath $Cli -PathType Leaf)
    if (-not (Test-Path -LiteralPath $Cli -PathType Leaf)) { throw "Fresh Phase 11 CLI build missing." }

    Section "CLI Phase 11 model"
    $Describe = Capture $Cli @("describe")
    Log $Describe.Output
    Pass "describe exits successfully" ($Describe.ExitCode -eq 0)
    Pass "Phase marker is 11" ($Describe.Output -match "phase:\s*11")
    Pass "Windows ACL analysis advertised" ($Describe.Output -match "windows-acl-analysis:\s*available")
    Pass "multi-user ACL lab advertised" ($Describe.Output -match "windows-multi-user-acl-lab:\s*available")
    Pass "ACL testing is LabOnly" ($Describe.Output -match "windows-acl-safety-class:\s*lab-only")
    Pass "cross-user read/write probes advertised" ($Describe.Output -match "acl-cross-user-probes:\s*read,write")
    Pass "inheritance validation advertised" ($Describe.Output -match "acl-inheritance-validation:\s*available")

    $List = Capture $Cli @("list")
    Log $List.Output
    Pass "ACL test registered" ($List.Output -match "ACL-WINDOWS-001\s+lab-only\s+ACL")

    Section "Authorization gate"
    $Denied = Capture $Cli @(
        "windows-acl","analyze",
        "--input",(Join-Path $RepoRoot "does-not-matter.tsv"),
        "--output",(Join-Path $RunRoot "denied")
    )
    Log $Denied.Output
    Pass "ACL analysis without --lab-ack is refused" ($Denied.ExitCode -eq 7)

    Section "Temporary non-admin accounts"
    $OwnerSecurePassword = ConvertTo-SecureString $OwnerPassword -AsPlainText -Force
    $OtherSecurePassword = ConvertTo-SecureString $OtherPassword -AsPlainText -Force
    New-LocalUser -Name $OwnerUserName -Password $OwnerSecurePassword -AccountNeverExpires -PasswordNeverExpires -Description "Temporary DFSTL Phase 11 owner account" | Out-Null
    $OwnerUserCreated = $true
    New-LocalUser -Name $OtherUserName -Password $OtherSecurePassword -AccountNeverExpires -PasswordNeverExpires -Description "Temporary DFSTL Phase 11 cross-user account" | Out-Null
    $OtherUserCreated = $true

    $OwnerLocalUser = Get-LocalUser -Name $OwnerUserName
    $OtherLocalUser = Get-LocalUser -Name $OtherUserName
    Pass "temporary owner user exists" ($null -ne $OwnerLocalUser)
    Pass "temporary cross-user exists" ($null -ne $OtherLocalUser)

    $AdminSids = @(Get-LocalGroupMember -Group "Administrators" | ForEach-Object { $_.SID.Value })
    Pass "temporary owner is not an Administrator" (-not ($AdminSids -contains $OwnerLocalUser.SID.Value))
    Pass "temporary cross-user is not an Administrator" (-not ($AdminSids -contains $OtherLocalUser.SID.Value))

    New-Item -ItemType Directory -Force -Path $RunRoot | Out-Null
    $LabOutput = Join-Path $RunRoot "active-lab"
    $env:DFSTL_PHASE11_OWNER_PASSWORD = $OwnerPassword
    $env:DFSTL_PHASE11_OTHER_PASSWORD = $OtherPassword
    $OwnerUser = "$env:COMPUTERNAME\$OwnerUserName"
    $OtherUser = "$env:COMPUTERNAME\$OtherUserName"

    Section "Active multi-user ACL lab"
    $Lab = Capture "powershell.exe" @(
        "-NoProfile","-ExecutionPolicy","Bypass",
        "-File",(Join-Path $RepoRoot "scripts\invoke-phase11-acl-lab.ps1"),
        "-Root",$PublicLabRoot,
        "-OwnerUser",$OwnerUser,
        "-OtherUser",$OtherUser,
        "-Output",$LabOutput,
        "-LabAck"
    )
    Log $Lab.Output
    Pass "active multi-user ACL lab succeeds" ($Lab.ExitCode -eq 0)
    Pass "multi-user results exist" (Test-Path -LiteralPath (Join-Path $LabOutput "multi-user-results.json") -PathType Leaf)
    Pass "ACL snapshot exists" (Test-Path -LiteralPath (Join-Path $LabOutput "acl-snapshot.tsv") -PathType Leaf)
    if (Test-Path -LiteralPath (Join-Path $LabOutput "multi-user-results.json") -PathType Leaf) {
        $Multi = Get-Content -LiteralPath (Join-Path $LabOutput "multi-user-results.json") -Raw | ConvertFrom-Json
        Pass "multi-user schema_version is 1" ($Multi.schema_version -eq 1)
        Pass "owner user read is allowed" ($Multi.owner_user_read_allowed)
        Pass "owner user write is allowed" ($Multi.owner_user_write_allowed)
        Pass "Administrator read is allowed" ($Multi.administrator_read_allowed)
        Pass "Administrator write is allowed" ($Multi.administrator_write_allowed)
        Pass "cross-user read is denied" ($Multi.other_user_read_denied)
        Pass "cross-user write is denied" ($Multi.other_user_write_denied)
        Pass "five sensitive targets were restricted" ($Multi.restricted_targets -eq 5)
        Pass "multi-user result passed" ($Multi.passed)
        $MultiRaw = Get-Content -LiteralPath (Join-Path $LabOutput "multi-user-results.json") -Raw
        Pass "owner password not written to results" (-not $MultiRaw.Contains($OwnerPassword))
        Pass "cross-user password not written to results" (-not $MultiRaw.Contains($OtherPassword))
    }
    ValidateManifest $LabOutput

    Section "ACL snapshot analysis"
    $AnalysisOut = Join-Path $RunRoot "acl-analysis"
    $Analysis = Capture $Cli @(
        "windows-acl","analyze",
        "--input",(Join-Path $LabOutput "acl-snapshot.tsv"),
        "--output",$AnalysisOut,
        "--lab-ack",
        "--json"
    )
    Log $Analysis.Output
    Pass "unsafe inherited fixture produces finding status" ($Analysis.ExitCode -eq 1)
    try {
        $AnalysisJson = $Analysis.Output | ConvertFrom-Json
        Pass "ACL analysis schema_version is 1" ($AnalysisJson.schema_version -eq 1)
        Pass "ACL analysis contains findings" ($AnalysisJson.findings.Count -gt 0)
        Pass "broad-write finding detected" (@($AnalysisJson.findings | Where-Object { $_.code -eq "broad-write" }).Count -gt 0)
        Pass "inherited-broad-write finding detected" (@($AnalysisJson.findings | Where-Object { $_.code -eq "inherited-broad-write" }).Count -gt 0)
        Pass "sensitive inherited write finding detected" (@($AnalysisJson.findings | Where-Object { $_.code -eq "sensitive-inherited-write" }).Count -gt 0)
    } catch { $Failures.Add("ACL analysis JSON validation") }
    ValidateManifest $AnalysisOut

    Section "Clean ACL analyzer fixture"
    $CleanSnapshot = Join-Path $RunRoot "clean-acl.tsv"
    $Owner = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $CleanLines = @(
        ("C:\Lab\agent\agent-session.key" + [char]9 + $Owner + [char]9 + $Owner + [char]9 + "Allow" + [char]9 + "FullControl" + [char]9 + "false"),
        ("C:\Lab\agent\agent-session.key" + [char]9 + $Owner + [char]9 + "NT AUTHORITY\SYSTEM" + [char]9 + "Allow" + [char]9 + "FullControl" + [char]9 + "false")
    )
    [IO.File]::WriteAllLines($CleanSnapshot,$CleanLines,$Utf8NoBom)
    $CleanOut = Join-Path $RunRoot "clean-analysis"
    $Clean = Capture $Cli @(
        "windows-acl","analyze","--input",$CleanSnapshot,"--output",$CleanOut,"--lab-ack","--json"
    )
    Log $Clean.Output
    Pass "clean ACL fixture succeeds" ($Clean.ExitCode -eq 0)
    try {
        $CleanJson = $Clean.Output | ConvertFrom-Json
        Pass "clean ACL fixture has zero findings" ($CleanJson.clean -and $CleanJson.findings.Count -eq 0)
    } catch { $Failures.Add("clean ACL JSON validation") }
    ValidateManifest $CleanOut

    Section "Runner safety regression"
    $Safe = Capture $Cli @("run","--output",(Join-Path $RunRoot "safe"))
    Log $Safe.Output
    Pass "Safe runner succeeds" ($Safe.ExitCode -eq 0)
    Pass "ACL skipped under Safe" ($Safe.Output -match "ACL-WINDOWS-001\s+skipped")

    $Controlled = Capture $Cli @("run","--controlled","--output",(Join-Path $RunRoot "controlled"))
    Log $Controlled.Output
    Pass "Controlled runner succeeds" ($Controlled.ExitCode -eq 0)
    Pass "ACL remains skipped under Controlled" ($Controlled.Output -match "ACL-WINDOWS-001\s+skipped")

    $LabRunner = Capture $Cli @("run","--lab-ack","--output",(Join-Path $RunRoot "lab"))
    Log $LabRunner.Output
    Pass "LabOnly runner succeeds" ($LabRunner.ExitCode -eq 0)
    Pass "ACL passes under LabOnly" ($LabRunner.Output -match "ACL-WINDOWS-001\s+pass")

    Native "Release build" "cargo" @("build","--workspace","--release") | Out-Null

    Section "Final result"
    Log ("Finished:     " + (Get-Date).ToString("o"))
    Log ("Commit:       " + $Commit)
    Log ("Warnings:     " + $Warnings.Count)
    Log ("Failures:     " + $Failures.Count)
    if ($Failures.Count -eq 0) { Log ""; Log "PHASE 11 VALIDATION: PASS" }
    else {
        Log ""
        Log "Failures:"
        foreach ($FailureItem in $Failures) { Log ("  - " + $FailureItem) }
        Log ""
        Log "PHASE 11 VALIDATION: FAIL"
    }
}
catch {
    Section "Validation script failure"
    Log ("ERROR: " + $_.Exception.Message)
    $Failures.Add($_.Exception.Message)
    Log ""
    Log "PHASE 11 VALIDATION: FAIL"
}
finally {
    $env:DFSTL_PHASE11_OWNER_PASSWORD = $null
    $env:DFSTL_PHASE11_OTHER_PASSWORD = $null
    if ($OtherUserCreated) {
        try {
            Remove-LocalUser -Name $OtherUserName -ErrorAction Stop
            Log ("CLEANUP  removed temporary cross-user " + $OtherUserName)
        } catch {
            Log ("CLEANUP WARNING  unable to remove temporary cross-user " + $OtherUserName)
            $Warnings.Add("Temporary cross-user cleanup failed")
        }
    }
    if ($OwnerUserCreated) {
        try {
            Remove-LocalUser -Name $OwnerUserName -ErrorAction Stop
            Log ("CLEANUP  removed temporary owner user " + $OwnerUserName)
        } catch {
            Log ("CLEANUP WARNING  unable to remove temporary owner user " + $OwnerUserName)
            $Warnings.Add("Temporary owner-user cleanup failed")
        }
    }
    if (Test-Path -LiteralPath $PublicLabRoot) {
        try {
            Remove-Item -LiteralPath $PublicLabRoot -Recurse -Force -ErrorAction Stop
            Log ("CLEANUP  removed ACL lab root " + $PublicLabRoot)
        } catch {
            Log ("CLEANUP WARNING  unable to remove ACL lab root " + $PublicLabRoot)
            $Warnings.Add("ACL lab root cleanup failed")
        }
    }
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
if ($Failures.Count -gt 0 -or $Warnings.Count -gt 0) { exit 1 }
exit 0
