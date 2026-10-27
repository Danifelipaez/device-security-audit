# Read-only: checks whether each download client (installer / package manager) REJECTS
# known-bad TLS chains. A client that ACCEPTS one can be fed malware from a site that
# looks legitimately signed (e.g. the eMudhra CA key compromise, Oct 2026).
# Usage: pwsh -File trust-probe.ps1 [-Url <extra bad-chain URLs>]
param([string[]]$Url = @())
$ErrorActionPreference = 'SilentlyContinue'
$targets = @(
    'https://dv-g3b-emudhra.we-have-a-problem.com'      # forged via compromised eMudhra intermediate
    'https://dv-g3b-aaa-emudhra.we-have-a-problem.com'  # same, via Sectigo AAA cross-sign
    'https://revoked.badssl.com'
    'https://untrusted-root.badssl.com'
) + $Url

# Each probe returns $true if the connection SUCCEEDED (= client trusts the bad chain).
# -P (not -I): keep user site-packages, since that's the certifi the user's tools actually load;
# -s variant shows the base install's copy, which pip --user upgrades leave behind.
$py = { param($u, $mod, $flags = '-P') (python $flags -c "import ssl,urllib.request,$mod as c;urllib.request.urlopen('$u',context=ssl.create_default_context(cafile=c.where()),timeout=15);print('OK')" 2>$null) -eq 'OK' }
$probes = [ordered]@{
    'Windows (schannel/curl.exe)' = { param($u) (& "$env:SystemRoot\System32\curl.exe" -s -o NUL -w '%{http_code}' --max-time 15 $u) -match '^[1-5]\d\d$' }
    'Node.js'                     = { param($u) (node -e "require('https').get('$u',()=>console.log('OK')).on('error',()=>console.log('ERR'))") -eq 'OK' }
    'Python certifi (user)'       = { param($u) & $py $u 'certifi' }
    'Python certifi (base)'       = { param($u) & $py $u 'certifi' '-Ps' }
    'pip (vendored certifi)'      = { param($u) & $py $u 'pip._vendor.certifi' }
    'Git (http backend)'          = { param($u) git -c credential.helper= ls-remote $u 2>&1 | Select-String -Quiet -NotMatch 'SSL|certificate|unable to access' }
}
$need = @{ 'Node.js' = 'node'; 'Python certifi (user)' = 'python'; 'Python certifi (base)' = 'python'; 'pip (vendored certifi)' = 'python'; 'Git (http backend)' = 'git' }

$rows = foreach ($name in $probes.Keys) {
    if ($need[$name] -and -not (Get-Command $need[$name])) { continue }
    foreach ($u in $targets) {
        $ok = & $probes[$name] $u
        # Node/OpenSSL clients don't check revocation by default; that's a known limit, not a stale store.
        $verdict = if (-not $ok) { 'rejects' } elseif ($u -match 'revoked') { 'accepts (no revocation check)' } else { 'ACCEPTS (vulnerable)' }
        [pscustomobject]@{ Client = $name; Target = ([uri]$u).Host; Result = $verdict }
    }
}
$rows | Format-Table -AutoSize | Out-String -Width 200

# Windows auto-updates its trusted/disallowed CA lists; if this is stale or disabled, revocations never arrive.
$au = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate'
$pol = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot').DisableRootAutoUpdate
foreach ($k in 'LastSyncTime', 'DisallowedCertLastSyncTime') {
    if ($au.$k) { "{0}: {1:yyyy-MM-dd HH:mm}" -f $k, [DateTime]::FromFileTime([BitConverter]::ToInt64($au.$k, 0)) }
}
"DisableRootAutoUpdate policy: " + $(if ($pol) { "$pol  <-- revocations are NOT being received" } else { 'not set (good)' })
"pip vendored certifi: " + (python -I -c "import pip._vendor.certifi as c;print(c.contents().count('BEGIN CERT'),'certs')" 2>$null)
