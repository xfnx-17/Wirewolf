# Copy wirewolf.dll and its dependencies next to the Flutter exe.
# wirewolf.dll depends on llama.dll + ggml*.dll, and Windows resolves those
# relative to the EXE that loads them — so they must sit beside the Flutter exe.
#
# Usage:
#   .\copy_dlls.ps1            # copies to both Debug and Release if present
#   .\copy_dlls.ps1 -Config Debug

param(
    [string]$Config = "All"
)

$src = "D:\SideProject\build"
$runner = "D:\SideProject\flutter_app\build\windows\x64\runner"

$cudaBin = "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.1\bin\x64"

$allDlls = @(
    "$src\ffi\Release\wirewolf.dll",
    "$src\bin\Release\ggml-base.dll",
    "$src\bin\Release\ggml-cpu.dll",
    "$src\bin\Release\ggml-cuda.dll",
    "$src\bin\Release\ggml.dll",
    "$src\bin\Release\llama.dll",
    # CUDA runtime (required by ggml-cuda.dll; not on system PATH)
    "$cudaBin\cudart64_13.dll",
    "$cudaBin\cublas64_13.dll",
    "$cudaBin\cublasLt64_13.dll",
    # WinDivert inline-mode runtime (DLL + kernel driver .sys must sit beside exe)
    "$src\_deps\windivert-src\x64\WinDivert.dll",
    "$src\_deps\windivert-src\x64\WinDivert64.sys"
)

$targets = @()
if ($Config -eq "All" -or $Config -eq "Debug")   { $targets += "$runner\Debug" }
if ($Config -eq "All" -or $Config -eq "Release") { $targets += "$runner\Release" }

$copied = $false
foreach ($dst in $targets) {
    if (-not (Test-Path $dst)) { continue }
    foreach ($dll in $allDlls) {
        if (Test-Path $dll) {
            Copy-Item $dll $dst -Force
        } else {
            Write-Host "MISSING: $dll" -ForegroundColor Yellow
        }
    }
    # Bundle the threat-intel rules folder for convenience (optional at runtime)
    $rulesSrc = "D:\SideProject\rules"
    if (Test-Path $rulesSrc) {
        Copy-Item $rulesSrc "$dst\rules" -Recurse -Force
    }
    Write-Host "Copied DLLs to: $dst" -ForegroundColor Green
    $copied = $true
}

if (-not $copied) {
    Write-Host "No runner directory found. Build the Flutter app first (flutter run / flutter build windows)." -ForegroundColor Red
}
