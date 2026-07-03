#include "config_panel.hpp"
#include "IconsFontAwesome6.h"
#include "imgui.h"
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <commdlg.h>

static bool open_file_dialog(char *path, size_t path_size, const char *filter) {
  OPENFILENAMEA ofn;
  ZeroMemory(&ofn, sizeof(ofn));
  ofn.lStructSize = sizeof(ofn);
  ofn.lpstrFile = path;
  ofn.nMaxFile = (DWORD)path_size;
  ofn.lpstrFilter = filter;
  ofn.nFilterIndex = 1;
  ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
  return GetOpenFileNameA(&ofn) != FALSE;
}
#endif

void ConfigPanel::draw(WirewolfConfig &config, PipelineState state) {
  ImGui::Begin(ICON_FA_SLIDERS " Configuration");
  draw_content(config, state);
  ImGui::End();
}

void ConfigPanel::draw_content(WirewolfConfig &config, PipelineState state) {
  bool disabled = (state == PipelineState::Running ||
                   state == PipelineState::Starting ||
                   state == PipelineState::Stopping);

  if (disabled)
    ImGui::BeginDisabled();

  // --- Network Interface ---
  ImGui::SeparatorText("Network Capture");

  if (!interfaces_loaded_) {
    interfaces_ = PipelineController::list_interfaces();
    interfaces_loaded_ = true;

    // Try to match current config
    for (int i = 0; i < (int)interfaces_.size(); i++) {
      if (interfaces_[i].name == config.interface) {
        selected_interface_ = i;
        break;
      }
    }
  }

  ImGui::SameLine(ImGui::GetWindowWidth() - 80);
  if (ImGui::Button("Refresh")) {
    interfaces_ = PipelineController::list_interfaces();
    selected_interface_ = -1;
  }

  if (ImGui::BeginCombo("Interface",
                         selected_interface_ >= 0
                             ? interfaces_[selected_interface_]
                                   .description.c_str()
                             : "Select interface...")) {
    for (int i = 0; i < (int)interfaces_.size(); i++) {
      bool selected = (selected_interface_ == i);
      std::string label =
          interfaces_[i].description.empty()
              ? interfaces_[i].name
              : interfaces_[i].description + " (" + interfaces_[i].name + ")";
      if (ImGui::Selectable(label.c_str(), selected)) {
        selected_interface_ = i;
        config.interface = interfaces_[i].name;
      }
      if (selected)
        ImGui::SetItemDefaultFocus();
    }
    ImGui::EndCombo();
  }

  if (interfaces_.empty()) {
    ImGui::TextColored({1.0f, 0.6f, 0.0f, 1.0f},
                       "No interfaces found. Run as admin?");
  }

  // PCAP file alternative
  static char pcap_path[512] = "";
  if (config.interface.size() < sizeof(pcap_path))
    strncpy_s(pcap_path, sizeof(pcap_path), config.interface.c_str(), _TRUNCATE);
  if (ImGui::InputText("Or PCAP file", pcap_path, sizeof(pcap_path))) {
    config.interface = pcap_path;
    selected_interface_ = -1;
  }
#ifdef _WIN32
  ImGui::SameLine();
  if (ImGui::Button("Browse##pcap")) {
    if (open_file_dialog(pcap_path, sizeof(pcap_path),
                         "PCAP Files\0*.pcap;*.pcapng\0All Files\0*.*\0")) {
      config.interface = pcap_path;
      selected_interface_ = -1;
    }
  }
#endif

  // --- Model Paths ---
  ImGui::SeparatorText("Models");

  static char ov_path[512] = "";
  if (config.openvino_model_path.size() < sizeof(ov_path))
    strncpy_s(ov_path, sizeof(ov_path), config.openvino_model_path.c_str(), _TRUNCATE);
  if (ImGui::InputText("OpenVINO Model", ov_path, sizeof(ov_path))) {
    config.openvino_model_path = ov_path;
  }
#ifdef _WIN32
  ImGui::SameLine();
  if (ImGui::Button("Browse##ov")) {
    if (open_file_dialog(ov_path, sizeof(ov_path),
                         "OpenVINO Model\0*.xml\0All Files\0*.*\0")) {
      config.openvino_model_path = ov_path;
    }
  }
#endif

  static char llama_path[512] = "";
  if (config.llama_model_path.size() < sizeof(llama_path))
    strncpy_s(llama_path, sizeof(llama_path), config.llama_model_path.c_str(), _TRUNCATE);
  if (ImGui::InputText("LLaMA Model", llama_path, sizeof(llama_path))) {
    config.llama_model_path = llama_path;
  }
#ifdef _WIN32
  ImGui::SameLine();
  if (ImGui::Button("Browse##llama")) {
    if (open_file_dialog(llama_path, sizeof(llama_path),
                         "GGUF Model\0*.gguf\0All Files\0*.*\0")) {
      config.llama_model_path = llama_path;
    }
  }
#endif

  // --- Thresholds ---
  ImGui::SeparatorText("Filter Thresholds");

  ImGui::InputFloat("Entropy High", &config.entropy_high_threshold, 0.1f, 1.0f,
                    "%.2f");
  ImGui::InputFloat("Entropy Low", &config.entropy_low_threshold, 0.1f, 1.0f,
                    "%.2f");
  ImGui::InputFloat("Variance", &config.variance_threshold, 1000.0f, 10000.0f,
                    "%.0f");
  ImGui::InputFloat("Inter-arrival Floor", &config.inter_arrival_floor,
                    0.0001f, 0.001f, "%.4f");
  if (WirewolfConfig::openvino_compiled()) {
    ImGui::Checkbox("Use OpenVINO", &config.openvino_enabled);
    if (config.openvino_enabled) {
      ImGui::SliderFloat("NPU Threshold", &config.npu_threshold, 0.1f, 0.95f,
                         "%.2f");
      if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip(
            "Higher = fewer flows sent to LLM (less GPU load)\n"
            "Lower = more flows analyzed by LLM (more thorough)");
      }
    }
  } else {
    ImGui::BeginDisabled();
    bool dummy = false;
    ImGui::Checkbox("Use OpenVINO", &dummy);
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::TextColored({1.0f, 0.5f, 0.0f, 1.0f},
                       "(not compiled — rebuild with -OpenVINO)");
  }

  // --- Queue & LLM ---
  ImGui::SeparatorText("Pipeline Settings");

  int queue_cap = (int)config.queue_capacity;
  if (ImGui::InputInt("Queue Capacity", &queue_cap)) {
    config.queue_capacity = (size_t)std::max(1, queue_cap);
  }

  int payload_limit = (int)config.payload_char_limit;
  if (ImGui::InputInt("Payload Char Limit", &payload_limit)) {
    config.payload_char_limit = (size_t)std::max(1, payload_limit);
  }

  ImGui::InputInt("Max LLM Tokens", &config.max_tokens);
  ImGui::InputInt("GPU Layers", &config.n_gpu_layers);

  // --- Logging ---
  ImGui::SeparatorText("Logging");

  const char *log_levels[] = {"DEBUG", "INFO", "WARN", "ERROR"};
  ImGui::Combo("Log Level", &config.log_level, log_levels, 4);

  // --- Validation ---
  if (!config.valid()) {
    ImGui::Separator();
    ImGui::TextColored({1.0f, 0.4f, 0.4f, 1.0f},
                       "Set interface, OpenVINO model, and LLaMA model paths.");
  }

  if (disabled)
    ImGui::EndDisabled();
}
