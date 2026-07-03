<#
.SYNOPSIS
  Copy the freshly-built engine FFI dll (and its runtime deps) into the Flutter
  Windows runner output, so the desktop app loads the CURRENT engine instead of
  a stale wirewolf.dll (which makes the app fall back to DEMO mode when new FFI
  symbols are missing).

  Run this after rebuilding wirewolf_ffi:
     cmake --build build --config Release --target wirewolf_ffi
     .\scripts\deploy_engine_dll.ps1
#>
param(
  [string]$Runner = "flutter_app\build\windows\x64\runner\Release"
)
$ErrorActionPreference = "Stop"
$ffi = "build\ffi\Release\wirewolf.dll"
if (-not (Test-Path $ffi)) { throw "Build wirewolf_ffi first: $ffi not found" }
if (-not (Test-Path $Runner)) { throw "Runner dir not found (build the Flutter app once): $Runner" }

Copy-Item $ffi (Join-Path $Runner "wirewolf.dll") -Force
Write-Host "Deployed wirewolf.dll -> $Runner"

# llama/ggml/cuda deps (only needed if missing or changed)
foreach ($d in Get-ChildItem build\bin\Release\*.dll -ErrorAction SilentlyContinue) {
  $dest = Join-Path $Runner $d.Name
  if (-not (Test-Path $dest) -or $d.LastWriteTime -gt (Get-Item $dest).LastWriteTime) {
    Copy-Item $d.FullName $dest -Force
    Write-Host "Deployed dependency $($d.Name)"
  }
}
Write-Host "Done. Launch: $Runner\wirewolf_dashboard.exe"
