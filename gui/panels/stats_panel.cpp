#include "stats_panel.hpp"
#include "IconsFontAwesome6.h"
#include "imgui.h"
#include <cstdio>

void StatsPanel::update(const PipelineStats &stats) {
  // Track delta for sparkline
  float delta =
      static_cast<float>(stats.filter_passed) - (float)last_filter_passed_;
  last_filter_passed_ = stats.filter_passed;

  filter_pass_history_[history_offset_] = delta;
  history_offset_ = (history_offset_ + 1) % HISTORY_SIZE;

  stats_ = stats;
}

void StatsPanel::draw() {
  ImGui::Begin(ICON_FA_CHART_LINE " Pipeline Statistics");
  draw_content();
  ImGui::End();
}

void StatsPanel::draw_content() {
  // Filter stats
  ImGui::Text("Filter Passed:  %zu", stats_.filter_passed);
  ImGui::Text("Filter Dropped: %zu", stats_.filter_dropped);
  if (stats_.filter_deduped > 0)
    ImGui::Text("Deduped:        %zu", stats_.filter_deduped);
  ImGui::Text("Alerts Fired:   %zu", stats_.alerts_fired);

  size_t total = stats_.filter_passed + stats_.filter_dropped;
  if (total > 0) {
    float pass_rate = (float)stats_.filter_passed / (float)total * 100.0f;
    ImGui::Text("Pass Rate:      %.1f%%", pass_rate);
  }

  // Show filter device
  if (!stats_.filter_device.empty()) {
    ImVec4 color = {0.5f, 0.5f, 0.5f, 1.0f}; // gray = statistical
    if (stats_.filter_device == "NPU")
      color = {0.2f, 1.0f, 0.4f, 1.0f}; // green = NPU
    else if (stats_.filter_device == "CPU")
      color = {0.4f, 0.7f, 1.0f, 1.0f}; // blue = CPU (OpenVINO)
    ImGui::TextColored(color, "Filter Device:  %s",
                       stats_.filter_device.c_str());
  }

  // Show capture completion status for offline PCAP
  if (stats_.capture_finished) {
    ImGui::TextColored({0.3f, 1.0f, 0.6f, 1.0f}, "Capture Complete");
  }

  ImGui::Separator();
  ImGui::Text("Queue Status");

  // Queue 1: reassembly -> filter
  {
    float fill = 0.0f;
    if (stats_.queue_reassembly_to_filter_capacity > 0) {
      fill = (float)stats_.queue_reassembly_to_filter_depth /
             (float)stats_.queue_reassembly_to_filter_capacity;
    }
    char overlay[64];
    snprintf(overlay, sizeof(overlay), "Reassembly -> Filter: %zu / %zu",
             stats_.queue_reassembly_to_filter_depth,
             stats_.queue_reassembly_to_filter_capacity);
    ImGui::ProgressBar(fill, ImVec2(-1, 0), overlay);
    if (stats_.queue_reassembly_to_filter_drops > 0) {
      ImGui::SameLine();
      ImGui::TextColored({1.0f, 0.3f, 0.3f, 1.0f}, "(%zu drops)",
                         stats_.queue_reassembly_to_filter_drops);
    }
  }

  // Queue 2: filter -> LLM
  {
    float fill = 0.0f;
    if (stats_.queue_filter_to_llm_capacity > 0) {
      fill = (float)stats_.queue_filter_to_llm_depth /
             (float)stats_.queue_filter_to_llm_capacity;
    }
    char overlay[64];
    snprintf(overlay, sizeof(overlay), "Filter -> LLM: %zu / %zu",
             stats_.queue_filter_to_llm_depth,
             stats_.queue_filter_to_llm_capacity);
    ImGui::ProgressBar(fill, ImVec2(-1, 0), overlay);
    if (stats_.queue_filter_to_llm_drops > 0) {
      ImGui::SameLine();
      ImGui::TextColored({1.0f, 0.3f, 0.3f, 1.0f}, "(%zu drops)",
                         stats_.queue_filter_to_llm_drops);
    }
  }

  ImGui::Separator();
  ImGui::Text("Filter Pass Rate (recent)");

  // Sparkline — reorder ring buffer for display
  float ordered[HISTORY_SIZE];
  for (size_t i = 0; i < HISTORY_SIZE; i++) {
    ordered[i] = filter_pass_history_[(history_offset_ + i) % HISTORY_SIZE];
  }
  ImGui::PlotLines("##passrate", ordered, (int)HISTORY_SIZE, 0, nullptr, 0.0f,
                   FLT_MAX, ImVec2(-1, 80));
}
