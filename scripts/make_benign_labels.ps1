<#
.SYNOPSIS
  Build a benign-inclusive labels file for false-positive benchmarking.

  wirewolf_bench only counts false positives over pairs explicitly labeled
  BENIGN. The shipped label files list only malicious pairs, so precision is
  trivially 1.0. This enumerates EVERY host-pair in a capture (via
  `wirewolf_ipscan --pairs`), marks the known-attack pairs with their label,
  and labels everything else BENIGN — so a bench run reports a real FP rate.

.EXAMPLE
  .\scripts\make_benign_labels.ps1 `
     -Pcap datasets\friday_attack.pcap `
     -Attacks bench\labels.cicids.csv `
     -Out bench\labels.cicids.fp.csv
#>
param(
  [Parameter(Mandatory = $true)][string]$Pcap,
  [Parameter(Mandatory = $true)][string]$Attacks,
  [Parameter(Mandatory = $true)][string]$Out,
  [string]$IpScan = "build\Release\wirewolf_ipscan.exe"
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path $IpScan)) { throw "ipscan not found: $IpScan (build it first: cmake --build build --config Release --target wirewolf_ipscan)" }
if (-not (Test-Path $Pcap))   { throw "pcap not found: $Pcap" }
if (-not (Test-Path $Attacks)){ throw "attacks labels not found: $Attacks" }

# Attack pairs -> label, stored order-independently (both directions).
$attackLabel = @{}
foreach ($line in Get-Content $Attacks) {
  $t = $line.Trim()
  if ($t -eq "" -or $t.StartsWith("#")) { continue }
  $c = $t.Split(",")
  if ($c.Count -lt 3) { continue }
  $a = $c[0].Trim(); $b = $c[1].Trim(); $lab = $c[2].Trim()
  if ($lab -eq "") { $lab = "Attack" }
  $attackLabel["$a,$b"] = $lab
  $attackLabel["$b,$a"] = $lab
}
Write-Host "Loaded $($attackLabel.Count / 2) attack pairs from $Attacks"

# Enumerate all host-pairs in the capture.
Write-Host "Enumerating host-pairs in $Pcap ..."
$pairs = & $IpScan $Pcap "--pairs"

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# Auto-generated benign-inclusive labels for FP benchmarking")
$lines.Add("# Source pcap: $Pcap ; attacks: $Attacks ; generated: $(Get-Date -Format s)")
$mal = 0; $ben = 0
foreach ($p in $pairs) {
  $p = $p.Trim()
  if ($p -eq "" -or -not $p.Contains(",")) { continue }
  if ($attackLabel.ContainsKey($p)) {
    $lines.Add("$p,$($attackLabel[$p])"); $mal++
  } else {
    $lines.Add("$p,BENIGN"); $ben++
  }
}
Set-Content -Path $Out -Value $lines -Encoding ascii
Write-Host "Wrote $Out : $mal malicious + $ben benign pairs"
