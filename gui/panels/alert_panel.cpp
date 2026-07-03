#include "alert_panel.hpp"
#include "IconsFontAwesome6.h"
#include "imgui.h"
#include <chrono>
#include <cstdio>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

// Helper to format IP from uint32_t (stored in network byte order).
// Reads bytes directly to avoid endianness issues with bit-shifting.
static void format_ip(uint32_t ip_net_order, char *buf, size_t buf_size) {
  auto *b = reinterpret_cast<const uint8_t *>(&ip_net_order);
  snprintf(buf, buf_size, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

// Helper to format endpoint (IP:port), converting port from network order.
static void format_endpoint(uint32_t ip, uint16_t port_net_order, char *buf,
                            size_t buf_size) {
  char ip_buf[32];
  format_ip(ip, ip_buf, sizeof(ip_buf));
  snprintf(buf, buf_size, "%s:%u", ip_buf, ntohs(port_net_order));
}

// Infer traffic direction from well-known server ports.
static const char *infer_direction(uint16_t src_port_net,
                                   uint16_t dst_port_net) {
  auto is_server = [](uint16_t p) -> bool {
    switch (p) {
    case 20: case 21: case 22: case 23: case 25: case 53:
    case 80: case 110: case 143: case 443: case 445:
    case 993: case 995: case 3306: case 3389: case 5432:
    case 8080: case 8443:
      return true;
    default:
      return false;
    }
  };
  uint16_t sp = ntohs(src_port_net);
  uint16_t dp = ntohs(dst_port_net);
  if (is_server(dp) && !is_server(sp))
    return "client -> server (request)";
  if (is_server(sp) && !is_server(dp))
    return "server -> client (response)";
  return "unknown";
}

// Helper to format time
static void format_time(std::chrono::system_clock::time_point tp, char *buf,
                        size_t buf_size) {
  auto time_t = std::chrono::system_clock::to_time_t(tp);
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                tp.time_since_epoch()) %
            1000;
  std::tm tm_buf{};
#ifdef _WIN32
  localtime_s(&tm_buf, &time_t);
#else
  localtime_r(&time_t, &tm_buf);
#endif
  snprintf(buf, buf_size, "%02d:%02d:%02d.%03d", tm_buf.tm_hour,
           tm_buf.tm_min, tm_buf.tm_sec, (int)ms.count());
}

void AlertPanel::add_alert(ThreatAlert alert) {
  alerts_.push_back(std::move(alert));
  if (alerts_.size() > MAX_ALERTS) {
    // Adjust selected index when trimming
    size_t trim = alerts_.size() - MAX_ALERTS;
    if (selected_index_ >= 0) {
      selected_index_ -= (int)trim;
      if (selected_index_ < 0)
        selected_index_ = -1;
    }
    alerts_.erase(alerts_.begin(), alerts_.begin() + (int)trim);
  }
}

void AlertPanel::draw() {
  ImGui::Begin(ICON_FA_SHIELD_HALVED " Threat Alerts");
  draw_content();
  ImGui::End();
}

void AlertPanel::draw_content() {
  // Toolbar
  ImGui::InputTextWithHint("##filter", "Filter...", filter_buf_,
                           sizeof(filter_buf_));
  ImGui::SameLine();
  ImGui::Checkbox("Auto-scroll", &auto_scroll_);
  ImGui::SameLine();
  ImGui::Text("(%zu alerts)", alerts_.size());
  ImGui::SameLine();
  if (ImGui::Button("Clear")) {
    alerts_.clear();
    selected_index_ = -1;
  }

  ImGui::Separator();

  // Split: table on left, inspector on right
  float avail_width = ImGui::GetContentRegionAvail().x;
  float inspector_width =
      (selected_index_ >= 0) ? avail_width * 0.35f : 0.0f;
  float table_width = avail_width - inspector_width;

  // Left: alert table
  ImGui::BeginChild("AlertTableRegion", ImVec2(table_width, 0));
  draw_table();
  ImGui::EndChild();

  // Right: inspector (only when an alert is selected)
  if (selected_index_ >= 0 && selected_index_ < (int)alerts_.size()) {
    ImGui::SameLine();
    ImGui::BeginChild("InspectorRegion", ImVec2(0, 0), ImGuiChildFlags_Borders);
    draw_inspector();
    ImGui::EndChild();
  }
}

void AlertPanel::draw_table() {
  const ImGuiTableFlags flags =
      ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg |
      ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV |
      ImGuiTableFlags_ScrollY;

  if (ImGui::BeginTable("AlertsTable", 6, flags)) {
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 90.0f);
    ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 150.0f);
    ImGui::TableSetupColumn("Dest", ImGuiTableColumnFlags_WidthFixed, 150.0f);
    ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 65.0f);
    ImGui::TableSetupColumn("Sev", ImGuiTableColumnFlags_WidthFixed, 60.0f);
    ImGui::TableSetupColumn("Snippet", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableHeadersRow();

    bool has_filter = filter_buf_[0] != '\0';

    ImGuiListClipper clipper;
    clipper.Begin((int)alerts_.size());
    while (clipper.Step()) {
      for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; row++) {
        const auto &alert = alerts_[row];

        // Filter check
        if (has_filter) {
          bool match = false;
          if (strstr(alert.threat_type.c_str(), filter_buf_))
            match = true;
          if (strstr(alert.severity.c_str(), filter_buf_))
            match = true;
          if (strstr(alert.snippet.c_str(), filter_buf_))
            match = true;
          if (!match)
            continue;
        }

        ImGui::TableNextRow();
        bool is_selected = (selected_index_ == row);

        // Time
        ImGui::TableNextColumn();
        char time_buf[32];
        format_time(alert.timestamp, time_buf, sizeof(time_buf));

        // Append a unique ImGui ID suffix to avoid collisions when
        // multiple alerts share the same timestamp (e.g. Heartbleed bursts).
        char selectable_label[64];
        snprintf(selectable_label, sizeof(selectable_label), "%s##%d",
                 time_buf, row);

        // Make entire row selectable
        ImGuiSelectableFlags sel_flags =
            ImGuiSelectableFlags_SpanAllColumns |
            ImGuiSelectableFlags_AllowOverlap;
        if (ImGui::Selectable(selectable_label, is_selected, sel_flags)) {
          selected_index_ = (selected_index_ == row) ? -1 : row;
        }

        // Source
        ImGui::TableNextColumn();
        char src_buf[48];
        format_endpoint(alert.connection.src_ip, alert.connection.src_port,
                        src_buf, sizeof(src_buf));
        ImGui::TextUnformatted(src_buf);

        // Destination
        ImGui::TableNextColumn();
        char dst_buf[48];
        format_endpoint(alert.connection.dst_ip, alert.connection.dst_port,
                        dst_buf, sizeof(dst_buf));
        ImGui::TextUnformatted(dst_buf);

        // Threat type
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(alert.threat_type.c_str());

        // Severity (color-coded with CVSS)
        ImGui::TableNextColumn();
        {
          char cvss_buf[32];
          std::snprintf(cvss_buf, sizeof(cvss_buf), "%s (%.1f)",
                        alert.severity_info.label(), alert.severity_info.cvss);
          switch (alert.severity_info.level) {
          case Severity::Critical:
            ImGui::TextColored({1.0f, 0.0f, 0.6f, 1.0f}, "%s", cvss_buf);
            break;
          case Severity::High:
            ImGui::TextColored({1.0f, 0.2f, 0.2f, 1.0f}, "%s", cvss_buf);
            break;
          case Severity::Medium:
            ImGui::TextColored({1.0f, 0.6f, 0.0f, 1.0f}, "%s", cvss_buf);
            break;
          case Severity::Low:
            ImGui::TextColored({1.0f, 1.0f, 0.0f, 1.0f}, "%s", cvss_buf);
            break;
          default:
            ImGui::TextUnformatted(cvss_buf);
            break;
          }
        }

        // Snippet
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(alert.snippet.c_str());
      }
    }

    if (auto_scroll_ && ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
      ImGui::SetScrollHereY(1.0f);

    ImGui::EndTable();
  }
}

void AlertPanel::draw_inspector() {
  if (selected_index_ < 0 || selected_index_ >= (int)alerts_.size())
    return;

  const auto &alert = alerts_[selected_index_];

  ImGui::Text("Inspector — Alert #%d", selected_index_ + 1);
  ImGui::Separator();

  // Connection info
  char src_buf[48], dst_buf[48], time_buf[32];
  format_endpoint(alert.connection.src_ip, alert.connection.src_port, src_buf,
                  sizeof(src_buf));
  format_endpoint(alert.connection.dst_ip, alert.connection.dst_port, dst_buf,
                  sizeof(dst_buf));
  format_time(alert.timestamp, time_buf, sizeof(time_buf));

  // Direction from port analysis
  const char *direction = infer_direction(alert.connection.src_port,
                                          alert.connection.dst_port);

  ImGui::Text("Time:      %s", time_buf);
  ImGui::Text("Source:    %s", src_buf);
  ImGui::Text("Dest:      %s", dst_buf);

  // Color the direction: requests are neutral, responses get a distinct color
  // so analysts can quickly spot server→client alerts (which are unusual).
  if (strstr(direction, "response")) {
    ImGui::TextColored({0.4f, 0.8f, 1.0f, 1.0f}, "Direction: %s", direction);
  } else {
    ImGui::Text("Direction: %s", direction);
  }

  ImGui::Text("Type:      %s", alert.threat_type.c_str());

  {
    std::string sev_str = alert.severity_info.format();
    switch (alert.severity_info.level) {
    case Severity::Critical:
      ImGui::TextColored({1.0f, 0.0f, 0.6f, 1.0f}, "Severity:  %s", sev_str.c_str());
      break;
    case Severity::High:
      ImGui::TextColored({1.0f, 0.2f, 0.2f, 1.0f}, "Severity:  %s", sev_str.c_str());
      break;
    case Severity::Medium:
      ImGui::TextColored({1.0f, 0.6f, 0.0f, 1.0f}, "Severity:  %s", sev_str.c_str());
      break;
    default:
      ImGui::Text("Severity:  %s", sev_str.c_str());
      break;
    }
  }

  ImGui::Separator();

  // LLM JSON output
  ImGui::TextColored({0.4f, 0.8f, 1.0f, 1.0f}, "LLM Output");
  ImGui::BeginChild("InspectorJSON", ImVec2(0, 80), ImGuiChildFlags_Borders,
                    ImGuiWindowFlags_HorizontalScrollbar);
  ImGui::TextWrapped("%s", alert.raw_llm_output.c_str());
  ImGui::EndChild();

  ImGui::Separator();

  // Full reassembled payload
  ImGui::TextColored({0.4f, 0.8f, 1.0f, 1.0f}, "Reassembled Payload (%zu chars)",
                     alert.payload_text.size());
  ImGui::BeginChild("InspectorPayload", ImVec2(0, 0), ImGuiChildFlags_Borders,
                    ImGuiWindowFlags_HorizontalScrollbar);
  if (!alert.payload_text.empty()) {
    ImGui::TextUnformatted(alert.payload_text.c_str(),
                           alert.payload_text.c_str() +
                               alert.payload_text.size());
  } else {
    ImGui::TextColored({0.5f, 0.5f, 0.5f, 1.0f}, "(no payload captured)");
  }
  ImGui::EndChild();
}
