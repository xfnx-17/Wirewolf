<#
.SYNOPSIS
  Run the Wirewolf accuracy benchmark (precision / recall / F1 + FP rate)
  and write a Markdown summary. Requires the LLM model (GGUF) — wirewolf_bench
  runs the full pipeline.

.DESCRIPTION
  RECALL (detection) is measured on the shipped labeled captures (neris, cicids).
  Their precision is trivially 1.0 because those captures are attack-only
  excerpts with no benign traffic.

  FALSE-POSITIVE rate requires a capture that CONTAINS benign traffic (e.g. the
  full CICIDS Friday-WorkingHours.pcap). Pass it via -FpPcap (+ the known-attack
  labels via -FpAttacks); the script auto-generates benign-inclusive labels for
  it (via make_benign_labels.ps1) and reports a real FP rate.

.EXAMPLE
  # recall only (datasets in repo)
  .\scripts\run_benchmark.ps1 -Model models\llama-3.1-8b-q4.gguf

.EXAMPLE
  # add a real FP measurement on a benign-containing capture
  .\scripts\run_benchmark.ps1 -Model models\llama-3.1-8b-q4.gguf `
     -FpPcap D:\caps\Friday-WorkingHours.pcap -FpAttacks bench\labels.cicids.csv
#>
param(
  [Parameter(Mandatory = $true)][string]$Model,
  [string]$OpenVINO = "",
  [string]$FpPcap = "",
  [string]$FpAttacks = "bench\labels.cicids.csv",
  [string]$Bench = "build\Release\wirewolf_bench.exe",
  [string]$OutDir = "bench_report"
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path $Bench)) { throw "wirewolf_bench not found: $Bench (build it: cmake --build build --config Release --target wirewolf_bench)" }
if (-not (Test-Path $Model)) { throw "model not found: $Model" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# Recall datasets shipped in the repo (attack-only → precision trivially 1.0).
$runs = @(
  @{ Name = "neris";  Pcap = "datasets\botnet-capture-20110810-neris.pcap"; Labels = "bench\labels.neris.csv" }
  @{ Name = "cicids"; Pcap = "datasets\friday_attack.pcap";                 Labels = "bench\labels.cicids.csv" }
)

# Optional FP run on a benign-containing capture supplied by the user.
if ($FpPcap -ne "") {
  if (-not (Test-Path $FpPcap)) { throw "FpPcap not found: $FpPcap" }
  $fpLabels = Join-Path $OutDir "labels.fp.csv"
  Write-Host "=== Generating benign-inclusive labels for $FpPcap ==="
  & "$PSScriptRoot\make_benign_labels.ps1" -Pcap $FpPcap -Attacks $FpAttacks -Out $fpLabels
  $runs += @{ Name = "fp"; Pcap = $FpPcap; Labels = $fpLabels }
}

$summary = New-Object System.Collections.Generic.List[string]
$summary.Add("# Wirewolf Benchmark Report")
$summary.Add("")
$summary.Add("_Generated $(Get-Date -Format s) - model: $Model_")
$summary.Add("")
$summary.Add("| Dataset | TP | FP | FN | TN | Precision | Recall | F1 | FP rate |")
$summary.Add("|---|---|---|---|---|---|---|---|---|")

foreach ($r in $runs) {
  if (-not (Test-Path $r.Pcap))   { Write-Host "skip $($r.Name): missing $($r.Pcap)"; continue }
  if (-not (Test-Path $r.Labels)) { Write-Host "skip $($r.Name): missing $($r.Labels)"; continue }

  Write-Host "=== Running $($r.Name) ==="
  $log = Join-Path $OutDir "$($r.Name).txt"
  $bargs = @($r.Pcap, $r.Labels, $Model)
  if ($OpenVINO -ne "") { $bargs += @("--openvino", $OpenVINO) }
  & $Bench @bargs 2>&1 | Tee-Object -FilePath $log | Out-Host

  $txt = Get-Content $log -Raw
  $cm  = [regex]::Match($txt, "TP=(\d+)\s+FP=(\d+)\s+FN=(\d+)\s+TN=(\d+)")
  $pr  = [regex]::Match($txt, "Precision\s*:\s*([\d.]+)")
  $rc  = [regex]::Match($txt, "Recall\s*:\s*([\d.]+)")
  $f1  = [regex]::Match($txt, "F1 score\s*:\s*([\d.]+)")
  if ($cm.Success) {
    $fp = [int]$cm.Groups[2].Value; $tn = [int]$cm.Groups[4].Value
    $fpRate = if (($fp + $tn) -gt 0) { "{0:N4}" -f ($fp / ($fp + $tn)) } else { "n/a" }
    $summary.Add("| $($r.Name) | $($cm.Groups[1]) | $fp | $($cm.Groups[3]) | $tn | $($pr.Groups[1].Value) | $($rc.Groups[1].Value) | $($f1.Groups[1].Value) | $fpRate |")
  } else {
    $summary.Add("| $($r.Name) | (see $log) ||||||||")
  }
}

$summary.Add("")
$summary.Add("FP rate = FP / (FP + TN), only meaningful on a capture with benign traffic (the *fp* row). Attack-only captures report TN=0 and Precision 1.0 by construction.")
$sumPath = Join-Path $OutDir "SUMMARY.md"
Set-Content -Path $sumPath -Value $summary -Encoding ascii
Write-Host ""
Write-Host "Report written to $sumPath"
