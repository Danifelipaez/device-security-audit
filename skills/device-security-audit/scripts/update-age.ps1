# Lists winget upgrades with the age of the target version's manifest in microsoft/winget-pkgs.
# The manifest merge date is a lower bound on "published at": if the manifest is older than
# -MinHours, the release is at least that old too.
# Needs: winget, gh (authenticated; unauthenticated API caps at 60 req/h).
# Output: CSV-ish table Id,Current,Available,Source,AgeHours,Eligible
param([int]$MinHours = 24)
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8

# Read-only: never accept source agreements on the user's behalf. If they were never accepted,
# winget refuses non-interactively and we say so instead of agreeing for them.
$lines = winget upgrade --include-unknown --disable-interactivity 2>$null | ForEach-Object { $_ -replace '^.*\r', '' }
$sep = ($lines | Select-String -Pattern '^-{10,}$' | Select -First 1).LineNumber
if (-not $sep) { Write-Error "Could not parse winget output. If winget's source agreements were never accepted, ask the user to run 'winget upgrade' once themselves."; exit 1 }
$header = $lines[$sep - 2]
# Column starts come from the header (localized names, fixed order: Name, Id, Version, Available, Source)
$starts = [regex]::Matches($header, '\S+') | ForEach-Object Index
$now = [DateTime]::UtcNow

$rows = foreach ($l in $lines[$sep..($lines.Count - 1)]) {
    if ($l.Length -lt $starts[4] -or $l -match '^\d+ ') { continue }   # footer like "31 upgrades available"
    $col = { param($i) $end = if ($i -lt 4) { $starts[$i + 1] } else { $l.Length }; $l.Substring($starts[$i], [Math]::Min($end, $l.Length) - $starts[$i]).Trim() }
    $id, $cur, $avail, $src = (& $col 1), (& $col 2), (& $col 3), (& $col 4)
    $age = $null
    if ($src -eq 'winget') {
        $path = "manifests/$($id.Substring(0,1).ToLower())/$($id -replace '\.', '/')/$avail"
        # oldest commit touching that version folder ~= when it was published to winget
        $date = gh api "repos/microsoft/winget-pkgs/commits?path=$path&per_page=100" --jq '.[-1].commit.committer.date' 2>$null
        if ($date) { $age = [int]($now - [DateTime]::Parse($date).ToUniversalTime()).TotalHours }
    }
    [pscustomobject]@{ Id = $id; Current = $cur; Available = $avail; Source = $src; AgeHours = $age
        Eligible = if ($age -eq $null) { 'unknown' } elseif ($age -ge $MinHours) { 'yes' } else { 'no' } }
}
$rows | Format-Table -AutoSize | Out-String -Width 200
