[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Output
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($env:OS -ne "Windows_NT") { throw "Windows ACL capture requires Windows." }
if (Test-Path -LiteralPath $Output) { throw "Output already exists: $Output" }

$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$Targets = New-Object System.Collections.Generic.List[string]

if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    $AgentRoot = Join-Path $env:LOCALAPPDATA "DragonForge\agent"
    foreach ($Path in @(
        $AgentRoot,
        (Join-Path $AgentRoot "agent-session.key"),
        (Join-Path $AgentRoot "agent-runtime.json"),
        (Join-Path $AgentRoot "agent.lock")
    )) {
        if (Test-Path -LiteralPath $Path) { $Targets.Add($Path) }
    }
}

if (-not [string]::IsNullOrWhiteSpace($env:PROGRAMDATA)) {
    $ServiceRoot = Join-Path $env:PROGRAMDATA "DragonForge\Security\privileged-service"
    foreach ($Path in @(
        $ServiceRoot,
        (Join-Path $ServiceRoot "service-config.json"),
        (Join-Path $ServiceRoot "audit.jsonl"),
        (Join-Path $ServiceRoot "firewall-policy-v1.json")
    )) {
        if (Test-Path -LiteralPath $Path) { $Targets.Add($Path) }
    }
}

$Lines = New-Object System.Collections.Generic.List[string]
foreach ($Target in $Targets | Sort-Object -Unique) {
    $Acl = Get-Acl -LiteralPath $Target
    foreach ($Ace in $Acl.Access) {
        $Rights = $Ace.FileSystemRights.ToString().Replace([char]9," ")
        $Line = @(
            $Target,
            $Acl.Owner,
            $Ace.IdentityReference.Value,
            $Ace.AccessControlType.ToString(),
            $Rights,
            $Ace.IsInherited.ToString().ToLowerInvariant()
        ) -join [char]9
        $Lines.Add($Line)
    }
}

[IO.File]::WriteAllLines($Output,$Lines,$Utf8NoBom)
Write-Host ("Captured ACL records: " + $Lines.Count)
Write-Host ("Output: " + $Output)
