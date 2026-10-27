# Read-only: decide whether a downloaded installer is what it claims to be.
# A valid Authenticode signature alone is NOT enough: certificates get stolen (Nvidia/Lapsus$),
# bought from signing-as-a-service crews (Fox Tempest, 72h certs), or issued by a compromised CA (eMudhra).
# Usage: pwsh -File verify-download.ps1 -Path setup.exe -ExpectedPublisher 'VideoLAN' [-Sha256 <hash from vendor/winget manifest>]
param([Parameter(Mandatory)][string]$Path, [string]$ExpectedPublisher, [string]$Sha256)
$ErrorActionPreference = 'SilentlyContinue'
$warn = [Collections.Generic.List[string]]::new()
$item = Get-Item -LiteralPath $Path
$hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
$sig = Get-AuthenticodeSignature -LiteralPath $Path
$cert = $sig.SignerCertificate

"File:      $($item.FullName)"
"SHA256:    $hash"
if ($Sha256) { if ($hash -ne $Sha256.ToUpper()) { $warn.Add('Hash does NOT match the expected value') } else { 'Hash:      matches expected' } }

# Where did it come from? Mark-of-the-Web keeps the real download URL, which defeats look-alike names.
$zone = Get-Content -LiteralPath $Path -Stream Zone.Identifier
if ($zone) { $zone | Select-String '^(HostUrl|ReferrerUrl)=' | ForEach-Object { "Origin:    $($_.Line)" } } else { 'Origin:    no Mark-of-the-Web (copied, extracted, or MOTW stripped)' }

"Signature: $($sig.Status)"
if ($sig.Status -ne 'Valid') { $warn.Add("Signature status is $($sig.Status)") }
if ($cert) {
    "Signer:    $($cert.Subject)"
    "Issuer:    $($cert.Issuer)"
    $life = ($cert.NotAfter - $cert.NotBefore).TotalDays
    "Validity:  $($cert.NotBefore.ToString('yyyy-MM-dd')) -> $($cert.NotAfter.ToString('yyyy-MM-dd')) ($([int]$life) days)"
    if ($life -le 7) { $warn.Add("Signing certificate lives only $([int]$life) days: short-lived certs are the Fox Tempest malware-signing pattern unless the vendor is known to use Azure Trusted/Artifact Signing") }
    if ((Get-Date) - $cert.NotBefore -lt [TimeSpan]::FromDays(14)) { $warn.Add('Signing certificate was issued less than 14 days ago') }
    if ($ExpectedPublisher -and $cert.Subject -notmatch [regex]::Escape($ExpectedPublisher)) { $warn.Add("Signer does not match expected publisher '$ExpectedPublisher'") }

    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    $chain.ChainPolicy.RevocationMode = 'Online'
    $null = $chain.Build($cert)
    "Chain:"; $chain.ChainElements | ForEach-Object { "  - $($_.Certificate.Subject)" }
    # An expired signer is fine when a trusted timestamp proves it signed while valid (WinVerifyTrust already said Valid).
    $ignore = @('NoError') + $(if ($sig.TimeStamperCertificate -and $sig.Status -eq 'Valid') { 'NotTimeValid' })
    $chain.ChainStatus | Where-Object { "$($_.Status)" -notin $ignore } | ForEach-Object { $warn.Add("Chain: $($_.StatusInformation.Trim())") }
    $disallowed = (Get-ChildItem Cert:\LocalMachine\Disallowed, Cert:\CurrentUser\Disallowed).Thumbprint
    $bad = $chain.ChainElements.Certificate | Where-Object { $_.Thumbprint -in $disallowed -or $_.Subject -match 'emSign|eMudhra' }
    if ($bad) { $warn.Add("Chain includes a distrusted/compromised CA: $(($bad.Subject) -join '; ')") }
    if ($sig.TimeStamperCertificate) { "Timestamp: $($sig.TimeStamperCertificate.Subject)" } else { $warn.Add('No countersigned timestamp') }
}

if ($warn.Count) { "`nVERDICT: DO NOT RUN"; $warn | ForEach-Object { "  ! $_" } } else { "`nVERDICT: no red flags (still prefer winget/vendor domain over third-party mirrors)" }
