#include "activity_panel.hpp"
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

static const char *action_name(FlowAction action) {
  switch (action) {
  case FlowAction::Filtered:
    return "Filtered";
  case FlowAction::PassedToLLM:
    return "-> LLM";
  case FlowAction::LLMCleared:
    return "Cleared";
  default:
    return "?";
  }
}

static ImVec4 action_color(FlowAction action) {
  switch (action) {
  case FlowAction::Filtered:
    return {0.5f, 0.5f, 0.5f, 1.0f}; // gray
  case FlowAction::PassedToLLM:
    return {1.0f, 0.8f, 0.0f, 1.0f}; // yellow
  case FlowAction::LLMCleared:
    return {0.2f, 1.0f, 0.4f, 1.0f}; // green
  default:
    return {1.0f, 1.0f, 1.0f, 1.0f};
  }
}

void ActivityPanel::add_event(FlowEvent event) {
  events_.push_back(std::move(event));
  if (events_.size() > MAX_EVENTS) {
    size_t trim = events_.size() - MAX_EVENTS;
    events_.erase(events_.begin(), events_.begin() + (int)trim);
  }
}

void ActivityPanel::clear() { events_.clear(); }

void ActivityPanel::draw() {
  ImGui::Begin(ICON_FA_WAVE_SQUARE " Live Activity");
  draw_content();
  ImGui::End();
}

void ActivityPanel::draw_content() {
  // Toolbar
  ImGui::InputTextWithHint("##actfilter", "Filter...", filter_buf_,
                           sizeof(filter_buf_));
  ImGui::SameLine();
  ImGui::Checkbox("Auto-scroll", &auto_scroll_);
  ImGui::SameLine();
  ImGui::Text("(%zu flows)", events_.size());
  ImGui::SameLine();
  if (ImGui::Button("Clear")) {
    clear();
  }

  ImGui::Separator();
  draw_table();
}

void ActivityPanel::draw_table() {
  const ImGuiTableFlags flags =
      ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg |
      ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV |
      ImGuiTableFlags_ScrollY;

  if (ImGui::BeginTable("ActivityTable", 6, flags)) {
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 90.0f);
    ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 150.0f);
    ImGui::TableSetupColumn("Dest", ImGuiTableColumnFlags_WidthFixed, 150.0f);
    ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 70.0f);
    ImGui::TableSetupColumn("Reason", ImGuiTableColumnFlags_WidthFixed, 100.0f);
    ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 70.0f);
    ImGui::TableHeadersRow();

    bool has_filter = filter_buf_[0] != '\0';

    ImGuiListClipper clipper;
    clipper.Begin((int)events_.size());
    while (clipper.Step()) {
      for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; row++) {
        const auto &ev = events_[row];

        // Filter check
        if (has_filter) {
          bool match = false;
          if (strstr(action_name(ev.action), filter_buf_))
            match = true;
          if (strstr(ev.reason.c_str(), filter_buf_))
            match = true;
          if (!match)
            continue;
        }

        ImGui::TableNextRow();

        // Time
        ImGui::TableNextColumn();
        char time_buf[32];
        format_time(ev.timestamp, time_buf, sizeof(time_buf));
        ImGui::TextUnformatted(time_buf);

        // Source
        ImGui::TableNextColumn();
        char src_buf[48];
        format_endpoint(ev.connection.src_ip, ev.connection.src_port, src_buf,
                        sizeof(src_buf));
        ImGui::TextUnformatted(src_buf);

        // Destination
        ImGui::TableNextColumn();
        char dst_buf[48];
        format_endpoint(ev.connection.dst_ip, ev.connection.dst_port, dst_buf,
                        sizeof(dst_buf));
        ImGui::TextUnformatted(dst_buf);

        // Action (color-coded)
        ImGui::TableNextColumn();
        ImGui::TextColored(action_color(ev.action), "%s",
                           action_name(ev.action));

        // Reason
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(ev.reason.c_str());

        // Size
        ImGui::TableNextColumn();
        if (ev.payload_size > 0) {
          ImGui::Text("%zu", ev.payload_size);
        } else {
          ImGui::TextColored({0.5f, 0.5f, 0.5f, 1.0f}, "-");
        }
      }
    }

    if (auto_scroll_ && ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
      ImGui::SetScrollHereY(1.0f);

    ImGui::EndTable();
  }
}
