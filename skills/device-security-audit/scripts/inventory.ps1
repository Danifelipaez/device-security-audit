# Read-only attack-surface inventory for a Windows host. Changes nothing.
# Usage: pwsh -File inventory.ps1 > inventory.txt
$ErrorActionPreference = 'SilentlyContinue'
function Section($t) { "`n== $t ==" }

Section 'OS'
Get-CimInstance Win32_OperatingSystem | Select Caption, Version, BuildNumber, LastBootUpTime | Format-List | Out-String
"Admin: " + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Section 'Listening TCP'
Get-NetTCPConnection -State Listen |
    Select LocalAddress, LocalPort, @{n = 'Proc'; e = { (Get-Process -Id $_.OwningProcess).ProcessName } } |
    Sort LocalPort | Format-Table -AutoSize | Out-String -Width 200

Section 'Listening UDP (non-loopback)'
Get-NetUDPEndpoint | ? { $_.LocalAddress -notmatch '^(127\.|::1)' } |
    Select LocalAddress, LocalPort, @{n = 'Proc'; e = { (Get-Process -Id $_.OwningProcess).ProcessName } } |
    Sort LocalPort | Format-Table -AutoSize | Out-String -Width 200

Section 'Running third-party services'
Get-CimInstance Win32_Service | ? { $_.State -eq 'Running' -and $_.PathName -notmatch '\\Windows\\(system32|SysWOW64)\\svchost' } |
    Select Name, StartMode, PathName | Format-Table -AutoSize | Out-String -Width 250

Section 'Unquoted service paths (local privesc)'
Get-CimInstance Win32_Service | ? { $_.PathName -match ' ' -and $_.PathName -notmatch '^"' -and $_.PathName -notmatch '^C:\\WINDOWS\\' } |
    Select Name, PathName | Format-Table -AutoSize | Out-String -Width 250

Section 'SYSTEM services whose binary or folder non-admins can modify (local privesc)'
$weak = 'Everyone|Todos|BUILTIN\\(Users|Usuarios)|Authenticated Users|Usuarios autentificados'
Get-CimInstance Win32_Service | ? { $_.StartName -match 'LocalSystem' -and $_.PathName -notmatch '^"?C:\\WINDOWS\\' } | ForEach-Object {
    $exe = if ($_.PathName -match '^"([^"]+)"') { $Matches[1] } else { ($_.PathName -split '\.exe', 2)[0] + '.exe' }
    foreach ($p in $exe, (Split-Path $exe)) {
        if (-not (Test-Path -LiteralPath $p)) { "{0} | MISSING {1} (re-creatable if folder writable)" -f $_.Name, $p; continue }
        $bad = (Get-Acl -LiteralPath $p).Access | ? { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference -match $weak -and $_.FileSystemRights -match 'FullControl|Modify|Write' }
        if ($bad) { "{0} | {1} | {2}" -f $_.Name, $p, (($bad | % { "$($_.IdentityReference):$($_.FileSystemRights)" }) -join '; ') }
    }
} | Sort -Unique

Section 'Loaded third-party kernel drivers (check SHA256 on loldrivers.io for BYOVD)'
Get-CimInstance Win32_SystemDriver | ? { $_.State -eq 'Running' -and $_.PathName -notmatch '\\Windows\\(System32|SysWOW64)\\(drivers|DriverStore)' } | ForEach-Object {
    $f = $_.PathName -replace '^\\\?\?\\', ''
    "{0} | {1} | {2}" -f $_.Name, $f, (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash
}
"Vulnerable driver blocklist: " + $(if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config').VulnerableDriverBlocklistEnable -eq 1) { 'on' } else { 'not set' })

Section 'CLIs'
foreach ($c in 'git','node','npm','python','pip','gh','docker','wsl','psql','java','code','claude','pnpm','bun','uv','go','rustc','curl','ollama','az','gcloud') {
    $p = (Get-Command $c -EA SilentlyContinue).Source
    if ($p) { "{0,-8} {1}  [{2}]" -f $c, ((& $c --version 2>&1 | Select -First 1) -replace '\0', ''), $p }
}

Section 'Defender'
Get-MpComputerStatus | Select AntivirusEnabled, RealTimeProtectionEnabled, IsTamperProtected, AntivirusSignatureLastUpdated, AMProductVersion | Format-List | Out-String

Section 'Firewall profiles'
Get-NetFirewallProfile | Select Name, Enabled, DefaultInboundAction | Format-Table | Out-String
Get-NetConnectionProfile | Select Name, NetworkCategory | Format-Table | Out-String

Section 'Inbound allow rules for third-party programs (ORPHAN = program no longer exists)'
# Read from the registry: works without admin (Get-NetFirewallRule doesn't) and isn't localized like netsh.
$fw = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
(Get-ItemProperty $fw).PSObject.Properties | ? Name -notlike 'PS*' | ForEach-Object {
    $r = @{}; foreach ($kv in $_.Value -split '\|') { $k, $v = $kv -split '=', 2; if ($v) { $r[$k] = @($r[$k]) + $v | ? { $_ } } }
    if ("$($r.Action)" -ne 'Allow' -or "$($r.Active)" -ne 'TRUE' -or "$($r.Dir)" -ne 'In') { return }
    $app = [Environment]::ExpandEnvironmentVariables("$($r.App)")
    if (-not $app -or $app -match '^(System$|C:\\WINDOWS\\)') { return }
    $orphan = if (-not (Test-Path -LiteralPath $app)) { 'ORPHAN ' } else { '' }
    $prof = if ($r.Profile) { $r.Profile -join ',' } else { 'All' }
    "{0}{1} | {2} | ports {3} | from {4} | {5}" -f $orphan, $r.Name, $prof, ("$($r.LPort)" -replace ' ', ','), ($(if ($r.RA4) { $r.RA4 -join ',' } else { 'Any' })), $app
} | Sort -Unique

Section 'SMB shares and share permissions (Everyone + enabled Guest = anonymous access)'
Get-SmbShare | ? Name -notmatch '^[A-Z]\$$|^ADMIN\$$|^IPC\$$' | ForEach-Object {
    $acc = (Get-SmbShareAccess -Name $_.Name | % { "$($_.AccountName):$($_.AccessRight)" }) -join ', '
    "{0} -> {1} | {2}" -f $_.Name, $_.Path, $acc
}

Section 'SMB / RDP / remote access'
"SMBv1 server: " + (Get-SmbServerConfiguration).EnableSMB1Protocol
"RDP deny: " + (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections
"WinRM: " + (Get-Service WinRM).Status
"sshd: " + $(if ($s = Get-Service sshd) { $s.Status } else { 'not installed' })

Section 'Accounts'
Get-LocalUser | Select Name, Enabled, PasswordRequired, LastLogon | Format-Table | Out-String
"Administrators: " + ((Get-LocalGroupMember -SID S-1-5-32-544).Name -join ', ')   # SID: group name is localized

Section 'Disk encryption / UAC'
"BitLocker C: " + ((manage-bde -status C: 2>&1 | Select-String 'Protection Status|Estado de protecc') -join ' ')
"UAC EnableLUA: " + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA

Section 'Recent hotfixes'
Get-HotFix | Sort InstalledOn -Desc | Select -First 5 HotFixID, InstalledOn | Format-Table | Out-String

Section 'Pending Windows Update'
try {
    (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search('IsInstalled=0 and IsHidden=0').Updates | % { $_.Title }
} catch { "WU query failed: $_" }

Section 'Startup entries'
Get-CimInstance Win32_StartupCommand | Select Name, Command | Format-Table -AutoSize | Out-String -Width 250
