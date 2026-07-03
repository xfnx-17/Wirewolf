Write-Host "Starting Wirewolf-CPP AI Model Downloads..." -ForegroundColor Cyan

# 1. Download the Quantized Llama 3.1 8B (Inference Layer - GPU)
Write-Host "Downloading llama.gguf (Llama-3.1-8B Q4_K_M) from Hugging Face (~4.9GB)..." -ForegroundColor Yellow
$llama_url = "https://huggingface.co/bartowski/Meta-Llama-3.1-8B-Instruct-GGUF/resolve/main/Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf"
Invoke-WebRequest -Uri $llama_url -OutFile "llama.gguf"
Write-Host "[OK] llama.gguf downloaded successfully." -ForegroundColor Green

# 2. Download a lightweight placeholder OpenVINO model (Filtration Layer - NPU)
# (Using Intel's retail face detection model strictly as a structural placeholder for NPU testing)
Write-Host "Downloading placeholder model.xml and model.bin from Intel Open Model Zoo..." -ForegroundColor Yellow
$xml_url = "https://storage.openvinotoolkit.org/repositories/open_model_zoo/2022.3/models_bin/1/face-detection-retail-0004/FP16/face-detection-retail-0004.xml"
$bin_url = "https://storage.openvinotoolkit.org/repositories/open_model_zoo/2022.3/models_bin/1/face-detection-retail-0004/FP16/face-detection-retail-0004.bin"

Invoke-WebRequest -Uri $xml_url -OutFile "model.xml"
Invoke-WebRequest -Uri $bin_url -OutFile "model.bin"
Write-Host "[OK] OpenVINO placeholder models downloaded successfully." -ForegroundColor Green

Write-Host "All models are present. You can now execute .\build.ps1!" -ForegroundColor Cyan