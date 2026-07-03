Write-Host "Starting Self-Healing OpenVINO Build Process..." -ForegroundColor Cyan

# 1. Handle existing directory and clone
$ErrorActionPreference = 'Stop'

if (Test-Path "openvino") {
    Write-Host "Wiping old 'openvino' directory to ensure a clean clone..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force "openvino"
}

Write-Host "Cloning OpenVINO 2026.0.0 branch..." -ForegroundColor Yellow
git clone --depth 1 -b 2026.0.0 https://github.com/openvinotoolkit/openvino.git
if (-not (Test-Path "openvino")) {
    Write-Host "[ERROR] Git clone failed." -ForegroundColor Red
    exit 1
}

cd openvino

$retries = 5
for ($i = 0; $i -lt $retries; $i++) {
    Write-Host "Updating submodules (Attempt $($i+1)/$retries)..."
    git submodule update --init --recursive --depth 1 --jobs 4
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Submodules updated successfully!" -ForegroundColor Green
        break
    }
    Write-Host "Submodule update failed. Retrying in 5 seconds..." -ForegroundColor Red
    Start-Sleep -Seconds 5
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Failed to update all submodules after $retries retries." -ForegroundColor Red
    exit 1
}
if (Test-Path "build") {
    Write-Host "Nuking old build directory and corrupted CMake cache..." -ForegroundColor Red
    Remove-Item -Recurse -Force "build"
}

Write-Host "Creating fresh build environment..." -ForegroundColor Yellow
mkdir build
cd build

# 4. Configure CMake
Write-Host "Configuring CMake for MSVC x64..." -ForegroundColor Yellow
cmake -A x64 `
    -DCMAKE_BUILD_TYPE=Release `
    -DENABLE_PYTHON=OFF `
    -DENABLE_TESTS=OFF `
    -DENABLE_SAMPLES=OFF `
    -DENABLE_INTEL_GPU=OFF `
    -DENABLE_INTEL_NPU=OFF `
    ..

# Check if CMake configuration actually succeeded before building
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] CMake configuration failed. Please ensure VS 2022 C++ workloads are installed!" -ForegroundColor Red
    exit
}

# 5. Execute parallel build
Write-Host "Building OpenVINO C++ libraries... (This will take time)" -ForegroundColor Cyan
$cores = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
cmake --build . --config Release --parallel $cores

if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] Build complete! Your libraries are ready." -ForegroundColor Green
}
else {
    Write-Host "[ERROR] Build failed during compilation." -ForegroundColor Red
}