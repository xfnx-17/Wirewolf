<#
.SYNOPSIS
  Assemble a self-contained, distributable Wirewolf bundle in dist\Wirewolf:
  the Flutter dashboard, the CLI and the ImGui GUI side by side, sharing one
  set of runtime DLLs (llama/ggml, CUDA, WinDivert, Npcap).

  Large AI models (.gguf) are NOT bundled — the target machine supplies its
  own model file and points the app at it (see the generated README.txt).

.EXAMPLE
  .\scripts\deploy.ps1                 # assemble dist\Wirewolf from existing builds
  .\scripts\deploy.ps1 -Build          # rebuild engine + dashboard first
  .\scripts\deploy.ps1 -Zip -Version 0.2.0
#>
param(
    [string]$Version = "0.1.0",
    [switch]$Build,
    [switch]$Zip
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

$runner = Join-Path $root "flutter_app\build\windows\x64\runner\Release"
$engine = Join-Path $root "build\Release"
$gui    = Join-Path $root "build\gui\Release"
$npcap  = "C:\Windows\System32\Npcap"

if ($Build) {
    & (Join-Path $root "build.ps1") -GUI
    if ($LASTEXITCODE -ne 0) { throw "Engine build failed" }
    Push-Location (Join-Path $root "flutter_app")
    flutter build windows --release
    if ($LASTEXITCODE -ne 0) { Pop-Location; throw "Flutter build failed" }
    & .\copy_dlls.ps1 -Config Release
    Pop-Location
}

foreach ($req in @("$runner\wirewolf_dashboard.exe", "$engine\wirewolf.exe")) {
    if (-not (Test-Path $req)) { throw "Missing $req - run with -Build (or build.ps1 / flutter build first)" }
}

$dist = Join-Path $root "dist\Wirewolf"
if (Test-Path $dist) { Remove-Item $dist -Recurse -Force -Confirm:$false }
New-Item -ItemType Directory -Force $dist | Out-Null

# Dashboard bundle is the base: exe + data\ + flutter DLLs + engine DLLs + rules\
Write-Host "Copying dashboard bundle..." -ForegroundColor Cyan
Copy-Item "$runner\*" $dist -Recurse

# CLI + GUI exes share the same runtime DLLs, so they sit in the same folder.
Write-Host "Adding CLI + GUI..." -ForegroundColor Cyan
Copy-Item "$engine\wirewolf.exe" $dist
if (Test-Path "$gui\wirewolf_gui.exe") {
    Copy-Item "$gui\wirewolf_gui.exe" $dist
    Copy-Item "$gui\*.ttf" $dist -ErrorAction SilentlyContinue
}

# Npcap user-mode DLLs (target still needs the Npcap driver installed).
Copy-Item "$npcap\wpcap.dll", "$npcap\Packet.dll" $dist -ErrorAction SilentlyContinue

# Small models: behavioral C2 detectors + OpenVINO pre-filter IR. No .gguf.
Write-Host "Adding models (behavioral + filter IR; no .gguf)..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force (Join-Path $dist "models") | Out-Null
Copy-Item (Join-Path $root "models\behavioral.*.model") (Join-Path $dist "models") -ErrorAction SilentlyContinue
Copy-Item (Join-Path $root "models\npu_filter.xml"), (Join-Path $root "models\npu_filter.bin") (Join-Path $dist "models") -ErrorAction SilentlyContinue

# Bundle README
@"
WIREWOLF $Version - local AI network threat detection
=====================================================

Contents
  wirewolf_dashboard.exe   Desktop dashboard (start here)
  wirewolf.exe             CLI engine (usage: wirewolf.exe <interface|file.pcap> ...)
  wirewolf_gui.exe         Lightweight ImGui frontend
  models\                  Behavioral C2 models + statistical filter IR
  rules\                   Threat-intel rules (bad IPs / domains / JA3 / signatures)

Requirements
  - Windows 10/11 x64
  - NVIDIA GPU with a current driver (CUDA 13 runtime DLLs are bundled)
  - Npcap installed, WinPcap-compatible mode (https://npcap.com) - for live capture
  - Administrator rights only for inline IPS mode (WinDivert driver)

LLM model (not bundled)
  Download a llama.cpp-compatible .gguf (e.g. Llama-3.1-8B Q4_K_M) and point
  the dashboard's Config screen (or the CLI's third argument) at it.
  Offline pcap analysis works without any capture driver.

Generated $((Get-Date).ToString("yyyy-MM-dd HH:mm")) by scripts\deploy.ps1
"@ | Set-Content (Join-Path $dist "README.txt")

$mb = [math]::Round(((Get-ChildItem $dist -Recurse | Measure-Object Length -Sum).Sum / 1MB), 0)
Write-Host "dist\Wirewolf assembled: $mb MB" -ForegroundColor Green

if ($Zip) {
    $zipPath = Join-Path $root "dist\Wirewolf-$Version-win-x64.zip"
    Write-Host "Zipping (this takes a minute)..." -ForegroundColor Cyan
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path $dist -DestinationPath $zipPath
    $zmb = [math]::Round((Get-Item $zipPath).Length / 1MB, 0)
    Write-Host "$zipPath ($zmb MB)" -ForegroundColor Green
}
