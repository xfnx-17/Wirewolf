<p align="center">
  <img src="branding/lockup.svg" alt="WIREWOLF" width="440">
</p>

Wirewolf is a high-performance, local AI-driven network threat detection engine built in C++. It analyzes network traffic in real-time or from offline capture files. The pipeline captures packets, reassembles TCP flows, and passes the payloads to a local Large Language Model (Llama 3.1 8B) to identify and classify potential threats into structured JSON alerts.

---

## 🏗️ Architecture Pipeline

1. **Packet Capture (Npcap / Offline PCAP):** Sniffs raw packets from a network interface or reads from `.pcap` files.
2. **TCP Reassembly:** Reconstructs interleaved packets back into continuous application-layer payloads.
3. **Primary Filtration (Statistical / OpenVINO):** Anomaly detection pre-filter using entropy analysis, packet variance, inter-arrival timing, and suspicious character ratios. Optional OpenVINO acceleration.
4. **Threat Analysis (LLM / llama.cpp):** Analyzes raw reassembled payloads using a quantized `Llama-3.1-8B-Instruct` model on NVIDIA GPU (CUDA).
5. **JSON Structuring:** Outputs strict JSON format for easy ingestion by SIEM or logging dashboards.

---

## ⚡ Engineered Mitigations

We have implemented several layers of protection against the "Reality Check" limitations of local LLM inference:

- **Context Window Truncation:** Payloads are truncated to a configurable limit (default **2048 characters**) before tokenization, preventing VRAM exhaustion.
- **Asynchronous Processing:** A **Thread-Safe Queue** with configurable capacity (default **1024 items**) decouples capture from inference. Overflow items are dropped with tracking, ensuring the capture engine stays live.
- **Statistical Pre-Filter:** Entropy analysis, packet length variance, inter-arrival timing, and suspicious character ratio detection filter ~85% of benign traffic before reaching the LLM.
- **Hallucination Suppression:** The inference engine utilizes a **Strict ChatML Few-Shot Template**. This explicitly trains the model on examples of benign traffic (Kerberos, DNS, domain handshakes) to return `[Empty {}]` instead of false positives.
- **Structured Logging:** Timestamped, severity-leveled logging across all components with thread-safe output.

---

## ⚙️ Prerequisites & Dependencies

- **Windows 10/11**
- **Visual Studio 2022** (Desktop development with C++)
- **CMake** (v3.20+)
- **NVIDIA CUDA Toolkit** (v12.x+)
- **Npcap SDK** (WinPcap compatibility enabled)

---

## 🚀 Getting Started

### 1. Download AI Models
```powershell
.\scripts\download_models.ps1
```

### 2. Build the Project
The build script automatically handles `llama.cpp` and `Npcap` fetching:
```powershell
.\build.ps1                     # Standard build
.\build.ps1 -Test               # Build + run unit tests
.\build.ps1 -OpenVINO           # Build with OpenVINO support
.\build.ps1 -Test -Run          # Build, test, then run
```

---

## 🎯 Running the Engine

### Analyze a Live Interface
```cmd
.\build\Release\wirewolf.exe "\Device\NPF_{GUID}" "models\model.xml" "models\llama.gguf"
```

### Analyze a PCAP File (Offline Mode)
Wirewolf automatically detects `.pcap` extensions and switches to offline mode:
```cmd
.\build\Release\wirewolf.exe "C:\path\to\capture.pcap" "models\model.xml" "models\llama.gguf"
```

### Runtime Options
```
--log-level N         0=DEBUG, 1=INFO (default), 2=WARN, 3=ERROR
--queue-capacity N    Max items per pipeline queue (default: 1024)
--payload-limit N     Max chars sent to LLM (default: 2048)
--max-tokens N        Max LLM output tokens (default: 512)
--max-flow-size N     Flow size trigger in bytes (default: 1MB)
--openvino            Use OpenVINO model instead of statistical filter
--entropy-high F      High entropy threshold (default: 7.0)
--entropy-low F       Low entropy threshold (default: 1.0)
```

---

## 📂 Project Structure

- `src/` - Implementation (Reassembly, Filter, LLM Worker Loop).
- `include/` - Headers (Config, Logger, Thread-Safe Queue, Packet Types).
- `tests/` - Unit tests (Catch2).
- `models/` - Quantized LLM (GGUF) and OpenVINO IR files.
- `scripts/` - Automation scripts for builders and model fetching.
- `CMakeLists.txt` - Configuration for CUDA/OpenVINO/Llama/Catch2 linking.

---

## 🔒 Threat Alert Format
Alerts are printed to `stdout` in strict JSON:
```json
{ 
  "threat_type": "SQLi", 
  "severity": "High", 
  "snippet": "SELECT * FROM users WHERE id='1' OR '1'='1'" 
}
```
If traffic is determined to be benign, the engine returns an empty object `{}`.
