[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Root,
    [Parameter(Mandatory=$true)][string]$OwnerUser,
    [Parameter(Mandatory=$true)][string]$OtherUser,
    [Parameter(Mandatory=$true)][string]$Output,
    [switch]$LabAck
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $LabAck) { throw "Phase 11 ACL lab is LabOnly; rerun with -LabAck." }
if ($env:OS -ne "Windows_NT") { throw "Phase 11 ACL lab requires Windows." }

function Resolve-Sid([string]$Name) {
    $account = New-Object System.Security.Principal.NTAccount($Name)
    return $account.Translate([System.Security.Principal.SecurityIdentifier])
}
function New-AllowRule(
    [System.Security.Principal.SecurityIdentifier]$Sid,
    [System.Security.AccessControl.FileSystemRights]$Rights,
    [System.Security.AccessControl.InheritanceFlags]$Inheritance,
    [System.Security.AccessControl.PropagationFlags]$Propagation
) {
    return New-Object System.Security.AccessControl.FileSystemAccessRule(
        $Sid,$Rights,$Inheritance,$Propagation,[System.Security.AccessControl.AccessControlType]::Allow
    )
}
function Set-RestrictedDirectoryAcl([string]$Path,[System.Security.Principal.SecurityIdentifier]$OwnerSid) {
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($ace in @($acl.Access)) { [void]$acl.RemoveAccessRuleAll($ace) }
    $acl.AddAccessRule((New-AllowRule $OwnerSid "FullControl" "ContainerInherit,ObjectInherit" "None"))
    $system = Resolve-Sid "NT AUTHORITY\SYSTEM"
    $admins = Resolve-Sid "BUILTIN\Administrators"
    $acl.AddAccessRule((New-AllowRule $system "FullControl" "ContainerInherit,ObjectInherit" "None"))
    $acl.AddAccessRule((New-AllowRule $admins "FullControl" "ContainerInherit,ObjectInherit" "None"))
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Invoke-AsUser([string]$User,[string]$Password,[string]$CommandLine) {
    $secure = ConvertTo-SecureString $Password -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($User,$secure)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($CommandLine))
    $p = Start-Process -FilePath "powershell.exe" -Credential $cred -ArgumentList @(
        "-NoProfile","-NonInteractive","-EncodedCommand",$encoded
    ) -Wait -PassThru -WindowStyle Hidden
    return $p.ExitCode
}
function Write-AclSnapshot([string]$Base,[string]$Destination) {
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($target in Get-ChildItem -LiteralPath $Base -Force -Recurse | Sort-Object FullName) {
        $acl = Get-Acl -LiteralPath $target.FullName
        foreach ($ace in $acl.Access) {
            $rights = $ace.FileSystemRights.ToString().Replace([char]9," ")
            $line = @(
                $target.FullName,
                $acl.Owner,
                $ace.IdentityReference.Value,
                $ace.AccessControlType.ToString(),
                $rights,
                $ace.IsInherited.ToString().ToLowerInvariant()
            ) -join [char]9
            $lines.Add($line)
        }
    }
    [IO.File]::WriteAllLines($Destination,$lines,[Text.UTF8Encoding]::new($false))
}

if (Test-Path -LiteralPath $Root) { throw "ACL lab root must not already exist: $Root" }
if (Test-Path -LiteralPath $Output) { throw "ACL lab output must not already exist: $Output" }

$ownerSid = Resolve-Sid $OwnerUser
$otherSid = Resolve-Sid $OtherUser

New-Item -ItemType Directory -Path $Root | Out-Null
$agent = Join-Path $Root "agent"
$priv = Join-Path $Root "privileged-service"
New-Item -ItemType Directory -Path $agent,$priv | Out-Null
Set-RestrictedDirectoryAcl $Root $ownerSid
Set-RestrictedDirectoryAcl $agent $ownerSid
Set-RestrictedDirectoryAcl $priv $ownerSid

$runtime = Join-Path $agent "agent-runtime.json"
$session = Join-Path $agent "agent-session.key"
$lock = Join-Path $agent "agent.lock"
$serviceConfig = Join-Path $priv "service-config.json"
$audit = Join-Path $priv "audit.jsonl"
[IO.File]::WriteAllText($runtime,'{"port":8787}',[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($session,'SYNTHETIC-SESSION-KEY',[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($lock,'1234',[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($serviceConfig,'{"schemaVersion":1}',[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($audit,'{"event":"synthetic"}',[Text.UTF8Encoding]::new($false))

foreach ($file in @($runtime,$session,$lock,$serviceConfig,$audit)) {
    $acl = Get-Acl -LiteralPath $file
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($ace in @($acl.Access)) { [void]$acl.RemoveAccessRuleAll($ace) }
    $acl.AddAccessRule((New-AllowRule $ownerSid "FullControl" "None" "None"))
    $acl.AddAccessRule((New-AllowRule (Resolve-Sid "NT AUTHORITY\SYSTEM") "FullControl" "None" "None"))
    $acl.AddAccessRule((New-AllowRule (Resolve-Sid "BUILTIN\Administrators") "FullControl" "None" "None"))
    Set-Acl -LiteralPath $file -AclObject $acl
}

$probeRead = @"
try {
  Get-Content -LiteralPath '$session' -Raw | Out-Null
  exit 0
} catch { exit 13 }
"@
$probeWrite = @"
try {
  [IO.File]::AppendAllText('$session','X')
  exit 0
} catch { exit 13 }
"@

$ownerPassword = $env:DFSTL_PHASE11_OWNER_PASSWORD
$otherPassword = $env:DFSTL_PHASE11_OTHER_PASSWORD
if ([string]::IsNullOrWhiteSpace($ownerPassword)) {
    throw "DFSTL_PHASE11_OWNER_PASSWORD is required for owner probes."
}
if ([string]::IsNullOrWhiteSpace($otherPassword)) {
    throw "DFSTL_PHASE11_OTHER_PASSWORD is required for cross-user probes."
}

$ownerReadExit = Invoke-AsUser $OwnerUser $ownerPassword $probeRead
$ownerWriteExit = Invoke-AsUser $OwnerUser $ownerPassword $probeWrite
$readExit = Invoke-AsUser $OtherUser $otherPassword $probeRead
$writeExit = Invoke-AsUser $OtherUser $otherPassword $probeWrite
$ownerRead = ($ownerReadExit -eq 0)
$ownerWrite = ($ownerWriteExit -eq 0)
$effectiveRead = ($readExit -eq 0)
$effectiveWrite = ($writeExit -eq 0)
$adminRead = $false
$adminWrite = $false
try {
    Get-Content -LiteralPath $session -Raw | Out-Null
    $adminRead = $true
    $stream = [IO.File]::Open($session,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    $stream.Dispose()
    $adminWrite = $true
} catch {
    $adminRead = $false
    $adminWrite = $false
}

$badDir = Join-Path $Root "broad-inheritance"
New-Item -ItemType Directory -Path $badDir | Out-Null
$badAcl = Get-Acl -LiteralPath $badDir
$badAcl.SetAccessRuleProtection($true,$false)
$badAcl.AddAccessRule((New-AllowRule (Resolve-Sid "BUILTIN\Users") "Modify" "ContainerInherit,ObjectInherit" "None"))
Set-Acl -LiteralPath $badDir -AclObject $badAcl
$badFile = Join-Path $badDir "agent-session.key"
[IO.File]::WriteAllText($badFile,'SYNTHETIC',[Text.UTF8Encoding]::new($false))

New-Item -ItemType Directory -Path $Output | Out-Null
$snapshot = Join-Path $Output "acl-snapshot.tsv"
Write-AclSnapshot $Root $snapshot

$result = [ordered]@{
    schema_version = 1
    owner_user = $OwnerUser
    owner_sid = $ownerSid.Value
    other_user = $OtherUser
    other_sid = $otherSid.Value
    restricted_targets = 5
    owner_user_read_allowed = $ownerRead
    owner_user_write_allowed = $ownerWrite
    administrator_read_allowed = $adminRead
    administrator_write_allowed = $adminWrite
    other_user_read_denied = (-not $effectiveRead)
    other_user_write_denied = (-not $effectiveWrite)
    inherited_broad_write_fixture = $badFile
    passed = ($ownerRead -and $ownerWrite -and $adminRead -and $adminWrite -and (-not $effectiveRead) -and (-not $effectiveWrite))
}
$json = $result | ConvertTo-Json -Depth 4
[IO.File]::WriteAllText((Join-Path $Output "multi-user-results.json"),$json,[Text.UTF8Encoding]::new($false))

$manifest = New-Object System.Collections.Generic.List[string]
foreach ($name in @("acl-snapshot.tsv","multi-user-results.json")) {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $Output $name)).Hash.ToLowerInvariant()
    $manifest.Add("$hash  $name")
}
[IO.File]::WriteAllLines((Join-Path $Output "SHA256SUMS"),$manifest,[Text.UTF8Encoding]::new($false))

if (-not $result.passed) { exit 1 }
exit 0
