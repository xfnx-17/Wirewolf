param(
    [switch]$Test,
    [switch]$OpenVINO,
    [switch]$GUI,
    [switch]$Run,
    [switch]$RunGUI,
    [string]$Pcap,
    [switch]$Clean
)

# Always run from the project root (where this script lives)
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

$CudaPath = "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.1"
$BuildDir = Join-Path $ProjectRoot "build"

if ($Clean -and (Test-Path $BuildDir)) {
    Write-Host "Cleaning build directory..." -ForegroundColor Yellow
    Remove-Item "$BuildDir\CMakeCache.txt" -ErrorAction SilentlyContinue
    Remove-Item "$BuildDir\CMakeFiles" -Recurse -ErrorAction SilentlyContinue
}

if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
}
Set-Location $BuildDir

# Detect if reconfigure is needed (options changed vs cached)
$needReconfigure = -not (Test-Path "CMakeCache.txt")
if (!$needReconfigure) {
    $cache = Get-Content "CMakeCache.txt" -Raw
    $cachedTests = $cache -match "WIREWOLF_BUILD_TESTS:BOOL=ON"
    $cachedOV = $cache -match "WIREWOLF_USE_OPENVINO:BOOL=ON"
    $cachedGUI = $cache -match "WIREWOLF_BUILD_GUI:BOOL=ON"
    if ($Test -ne $cachedTests -or $OpenVINO -ne $cachedOV -or $GUI -ne $cachedGUI) {
        Write-Host "Options changed, reconfiguring..." -ForegroundColor Yellow
        Remove-Item "CMakeCache.txt" -ErrorAction SilentlyContinue
        Remove-Item "CMakeFiles" -Recurse -ErrorAction SilentlyContinue
    }
}

$cmakeArgs = @("..", "-A", "x64", "-T", "cuda=$CudaPath")
if ($Test) {
    $cmakeArgs += "-DWIREWOLF_BUILD_TESTS=ON"
}
if ($OpenVINO) {
    $cmakeArgs += "-DWIREWOLF_USE_OPENVINO=ON"
}
if ($GUI) {
    $cmakeArgs += "-DWIREWOLF_BUILD_GUI=ON"
}

cmake @cmakeArgs
if ($LASTEXITCODE -ne 0) { Write-Host "CMake configure failed!" -ForegroundColor Red; exit 1 }

cmake --build . --config Release
if ($LASTEXITCODE -ne 0) { Write-Host "Build failed!" -ForegroundColor Red; exit 1 }

# Collect all output directories that contain executables
$outputDirs = @(".\Release")
if ($GUI -and (Test-Path ".\gui\Release")) {
    $outputDirs += ".\gui\Release"
}

# Copy required runtime DLLs to all output directories
foreach ($outDir in $outputDirs) {
    Copy-Item "C:\Windows\System32\Npcap\wpcap.dll", "C:\Windows\System32\Npcap\Packet.dll" -Destination "$outDir\" -ErrorAction SilentlyContinue

    # CUDA runtime DLLs (v13.x keeps them in bin\x64, older toolkits in bin)
    $cudaDlls = @("cudart64_*.dll", "cublas64_*.dll", "cublasLt64_*.dll")
    foreach ($dll in $cudaDlls) {
        Copy-Item "$CudaPath\bin\$dll" -Destination "$outDir\" -ErrorAction SilentlyContinue
        Copy-Item "$CudaPath\bin\x64\$dll" -Destination "$outDir\" -ErrorAction SilentlyContinue
    }

    # WinDivert runtime (DLL + kernel driver must sit beside the exe)
    Copy-Item ".\_deps\windivert-src\x64\WinDivert.dll", ".\_deps\windivert-src\x64\WinDivert64.sys" -Destination "$outDir\" -ErrorAction SilentlyContinue

    # llama.cpp runtime DLLs (llama.dll + ggml*.dll are emitted to bin\Release)
    Copy-Item ".\bin\Release\*.dll" -Destination "$outDir\" -ErrorAction SilentlyContinue
}

if ($OpenVINO) {
    # Find OpenVINO DLLs from pip package (preferred — has NPU plugin)
    $ovPipLibs = & python -c "import openvino, os; print(os.path.join(os.path.dirname(openvino.__file__), 'libs'))" 2>$null
    $ovDlls = @()
    if ($ovPipLibs -and (Test-Path $ovPipLibs)) {
        Write-Host "Copying OpenVINO DLLs from pip package (with NPU support)..." -ForegroundColor Cyan
        $ovDlls = @(
            "$ovPipLibs\openvino.dll",
            "$ovPipLibs\openvino_c.dll",
            "$ovPipLibs\openvino_ir_frontend.dll",
            "$ovPipLibs\openvino_intel_cpu_plugin.dll",
            "$ovPipLibs\openvino_intel_npu_plugin.dll",
            "$ovPipLibs\openvino_intel_npu_compiler.dll",
            "$ovPipLibs\openvino_auto_plugin.dll",
            "$ovPipLibs\openvino_hetero_plugin.dll",
            "$ovPipLibs\openvino_auto_batch_plugin.dll",
            "$ovPipLibs\tbb12.dll",
            "$ovPipLibs\tbbmalloc.dll"
        )
    } else {
        # Fallback: local source build (no NPU plugin)
        Write-Host "Copying OpenVINO DLLs from local build (no NPU support)..." -ForegroundColor Yellow
        $ovDlls = @(Get-ChildItem "..\openvino\bin\intel64\Release\openvino*.dll" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
        $tbbPath = "..\openvino\temp\Windows_AMD64\tbb\bin\tbb12.dll"
        if (Test-Path $tbbPath) { $ovDlls += (Resolve-Path $tbbPath).Path }
    }

    foreach ($outDir in $outputDirs) {
        foreach ($dll in $ovDlls) {
            Copy-Item $dll -Destination "$outDir\" -ErrorAction SilentlyContinue
        }
    }
}

if ($Test) {
    Write-Host "`nRunning tests..." -ForegroundColor Cyan
    .\Release\wirewolf_tests.exe --reporter compact
}

if ($Run) {
    $interface = "\Device\NPF_{16951121-998E-4BBE-B646-FA584E2B9F9C}"
    if ($Pcap) { $interface = $Pcap }
    Write-Host "`nStarting Wirewolf CLI..." -ForegroundColor Cyan
    Write-Host "  Interface/PCAP: $interface" -ForegroundColor Gray
    .\Release\wirewolf.exe "$interface" "..\models\npu_filter_cnn.xml" "..\models\Llama-3.1-WhiteRabbitNeo-2-8B-Q4_K_M.gguf" --openvino
}

if ($RunGUI) {
    if (-not (Test-Path ".\gui\Release\wirewolf_gui.exe")) {
        Write-Host "GUI not built! Use -GUI flag to build it first." -ForegroundColor Red
        exit 1
    }
    Write-Host "`nLaunching Wirewolf GUI..." -ForegroundColor Cyan
    Start-Process ".\gui\Release\wirewolf_gui.exe"
}
