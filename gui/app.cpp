#include "app.hpp"
#include "IconsFontAwesome6.h"
#include "imgui.h"
#include "logger.hpp"

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

static constexpr float SIDEBAR_WIDTH = 220.0f;

WirewolfApp::WirewolfApp() { setup_callbacks(); }

WirewolfApp::~WirewolfApp() {
  Logger::instance().set_callback(nullptr);
  controller_.stop();
}

void WirewolfApp::setup_callbacks() {
  controller_.set_on_threat_detected([this](const ThreatAlert &alert) {
    std::lock_guard<std::mutex> lock(alerts_mutex_);
    pending_alerts_.push_back(alert);
  });

  controller_.set_on_stats_update([this](const PipelineStats &stats) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    latest_stats_ = stats;
  });

  controller_.set_on_state_change([this](PipelineState state) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    current_state_ = state;
  });

  controller_.set_on_flow_event([this](const FlowEvent &ev) {
    std::lock_guard<std::mutex> lock(activity_mutex_);
    pending_activity_.push_back(ev);
  });

  Logger::instance().set_callback(
      [this](LogLevel level, const std::string &comp, const std::string &msg) {
        std::lock_guard<std::mutex> lock(logs_mutex_);
        pending_logs_.push_back({static_cast<int>(level), comp, msg});
      });
}

void WirewolfApp::process_pending_data() {
  {
    std::lock_guard<std::mutex> lock(alerts_mutex_);
    for (auto &a : pending_alerts_)
      alert_panel_.add_alert(std::move(a));
    pending_alerts_.clear();
  }
  {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_panel_.update(latest_stats_);
  }
  {
    std::lock_guard<std::mutex> lock(activity_mutex_);
    for (auto &ev : pending_activity_)
      activity_panel_.add_event(std::move(ev));
    pending_activity_.clear();
  }
  {
    std::lock_guard<std::mutex> lock(logs_mutex_);
    for (auto &l : pending_logs_)
      log_panel_.add_entry(l.level, l.component, l.message);
    pending_logs_.clear();
  }
}

void WirewolfApp::render() {
  process_pending_data();

  PipelineState st;
  {
    std::lock_guard<std::mutex> lock(state_mutex_);
    st = current_state_;
  }

  // Full-screen borderless main window
  const ImGuiViewport *viewport = ImGui::GetMainViewport();
  ImGui::SetNextWindowPos(viewport->Pos);
  ImGui::SetNextWindowSize(viewport->Size);

  ImGuiWindowFlags main_flags = ImGuiWindowFlags_NoDocking |
                                ImGuiWindowFlags_NoTitleBar |
                                ImGuiWindowFlags_NoCollapse |
                                ImGuiWindowFlags_NoResize |
                                ImGuiWindowFlags_NoMove |
                                ImGuiWindowFlags_NoBringToFrontOnFocus |
                                ImGuiWindowFlags_NoNavFocus;

  ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, {0, 0});
  ImGui::Begin("##MainShell", nullptr, main_flags);
  ImGui::PopStyleVar(3);

  // Layout: sidebar (left) + content (right)
  float full_h = ImGui::GetContentRegionAvail().y;
  float full_w = ImGui::GetContentRegionAvail().x;

  // --- Left Sidebar ---
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.03f, 0.03f, 0.03f, 1.0f));
  ImGui::BeginChild("##Sidebar", ImVec2(SIDEBAR_WIDTH, full_h),
                    ImGuiChildFlags_None);
  draw_sidebar(st);
  ImGui::EndChild();
  ImGui::PopStyleColor();

  // --- Main Content ---
  ImGui::SameLine(0, 0);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, {12, 12});
  ImGui::BeginChild("##Content", ImVec2(full_w - SIDEBAR_WIDTH, full_h),
                    ImGuiChildFlags_None);
  draw_content(st);
  ImGui::EndChild();
  ImGui::PopStyleVar();

  ImGui::End();
}

// Helper: full-width nav button with optional highlight
static bool NavButton(const char *label, bool is_active) {
  if (is_active) {
    ImGui::PushStyleColor(ImGuiCol_Button,
                          ImVec4(0.78f, 0.10f, 0.10f, 1.00f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                          ImVec4(0.85f, 0.15f, 0.15f, 1.00f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,
                          ImVec4(0.90f, 0.10f, 0.10f, 1.00f));
  } else {
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                          ImVec4(0.55f, 0.10f, 0.10f, 0.40f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,
                          ImVec4(0.55f, 0.10f, 0.10f, 0.70f));
  }

  ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.0f);
  ImGui::PushStyleVar(ImGuiStyleVar_ButtonTextAlign, ImVec2(0.0f, 0.5f));
  bool clicked = ImGui::Button(label, ImVec2(-1, 32));
  ImGui::PopStyleVar(2);
  ImGui::PopStyleColor(3);
  return clicked;
}

void WirewolfApp::draw_sidebar(PipelineState st) {
  ImGui::SetCursorPos({12, 16});

  // Logo / Title
  ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.78f, 0.10f, 0.10f, 1.00f));
  ImGui::Text(ICON_FA_SHIELD_HALVED);
  ImGui::PopStyleColor();
  ImGui::SameLine();
  ImGui::Text("Wirewolf");

  ImGui::Spacing();
  ImGui::Spacing();

  // --- Pipeline Control ---
  float btn_w = SIDEBAR_WIDTH - 24.0f;
  ImGui::SetCursorPosX(12);
  if (st == PipelineState::Stopped || st == PipelineState::Error) {
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.10f, 0.50f, 0.15f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                          ImVec4(0.15f, 0.60f, 0.20f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,
                          ImVec4(0.10f, 0.70f, 0.20f, 1.0f));
    if (ImGui::Button(ICON_FA_PLAY " Start Pipeline", ImVec2(btn_w, 30))) {
      if (config_.valid()) {
        Logger::instance().set_level(config_.log_level);
        controller_.start(config_);
      }
    }
    ImGui::PopStyleColor(3);
  } else if (st == PipelineState::Running) {
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.70f, 0.15f, 0.10f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                          ImVec4(0.80f, 0.20f, 0.15f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,
                          ImVec4(0.90f, 0.10f, 0.10f, 1.0f));
    if (ImGui::Button(ICON_FA_STOP " Stop Pipeline", ImVec2(btn_w, 30))) {
      controller_.stop();
    }
    ImGui::PopStyleColor(3);
  } else {
    ImGui::BeginDisabled();
    ImGui::Button(ICON_FA_SPINNER " Processing...", ImVec2(btn_w, 30));
    ImGui::EndDisabled();
  }

  ImGui::Spacing();
  ImGui::Separator();
  ImGui::Spacing();

  // --- Navigation: MONITORING ---
  ImGui::SetCursorPosX(12);
  ImGui::TextColored({0.50f, 0.50f, 0.50f, 1.0f}, "MONITORING");
  ImGui::Spacing();

  ImGui::SetCursorPosX(8);
  ImGui::BeginGroup();
  if (NavButton(ICON_FA_GAUGE_HIGH " Dashboard",
                current_page_ == NavPage::Dashboard))
    current_page_ = NavPage::Dashboard;
  if (NavButton(ICON_FA_SHIELD_HALVED " Threat Alerts",
                current_page_ == NavPage::Alerts))
    current_page_ = NavPage::Alerts;
  if (NavButton(ICON_FA_WAVE_SQUARE " Live Activity",
                current_page_ == NavPage::Activity))
    current_page_ = NavPage::Activity;
  ImGui::EndGroup();

  ImGui::Spacing();
  ImGui::SetCursorPosX(12);
  ImGui::TextColored({0.50f, 0.50f, 0.50f, 1.0f}, "PIPELINE");
  ImGui::Spacing();

  ImGui::SetCursorPosX(8);
  ImGui::BeginGroup();
  if (NavButton(ICON_FA_SLIDERS " Configuration",
                current_page_ == NavPage::Configuration))
    current_page_ = NavPage::Configuration;
  ImGui::EndGroup();

  ImGui::Spacing();
  ImGui::SetCursorPosX(12);
  ImGui::TextColored({0.50f, 0.50f, 0.50f, 1.0f}, "SYSTEM");
  ImGui::Spacing();

  ImGui::SetCursorPosX(8);
  ImGui::BeginGroup();
  if (NavButton(ICON_FA_TERMINAL " Log", current_page_ == NavPage::Log))
    current_page_ = NavPage::Log;
  ImGui::EndGroup();

  // --- Status indicator at bottom ---
  float bottom_y = ImGui::GetWindowHeight() - 50.0f;
  if (ImGui::GetCursorPosY() < bottom_y)
    ImGui::SetCursorPosY(bottom_y);

  ImGui::Separator();
  ImGui::SetCursorPosX(12);

  const char *status_text = "STOPPED";
  ImVec4 status_color = {0.5f, 0.5f, 0.5f, 1.0f};
  switch (st) {
  case PipelineState::Starting:
    status_text = "STARTING...";
    status_color = {1.0f, 0.8f, 0.0f, 1.0f};
    break;
  case PipelineState::Running:
    status_text = "RUNNING";
    status_color = {0.0f, 1.0f, 0.4f, 1.0f};
    break;
  case PipelineState::Stopping:
    status_text = "STOPPING...";
    status_color = {1.0f, 0.6f, 0.0f, 1.0f};
    break;
  case PipelineState::Error:
    status_text = "ERROR";
    status_color = {1.0f, 0.2f, 0.2f, 1.0f};
    break;
  default:
    break;
  }

  ImGui::TextColored(status_color, ICON_FA_CIRCLE " %s", status_text);
}

void WirewolfApp::draw_content(PipelineState st) {
  switch (current_page_) {
  case NavPage::Dashboard:
    draw_dashboard(st);
    break;
  case NavPage::Alerts:
    ImGui::BeginChild("##AlertsPage", ImVec2(0, 0), ImGuiChildFlags_Borders);
    alert_panel_.draw_content();
    ImGui::EndChild();
    break;
  case NavPage::Activity:
    ImGui::BeginChild("##ActivityPage", ImVec2(0, 0), ImGuiChildFlags_Borders);
    activity_panel_.draw_content();
    ImGui::EndChild();
    break;
  case NavPage::Configuration:
    ImGui::BeginChild("##ConfigPage", ImVec2(0, 0), ImGuiChildFlags_Borders);
    config_panel_.draw_content(config_, st);
    ImGui::EndChild();
    break;
  case NavPage::Log:
    ImGui::BeginChild("##LogPage", ImVec2(0, 0), ImGuiChildFlags_Borders);
    log_panel_.draw_content();
    ImGui::EndChild();
    break;
  }
}

void WirewolfApp::draw_dashboard(PipelineState st) {
  float avail_w = ImGui::GetContentRegionAvail().x;
  float card_spacing = 8.0f;
  float card_w = (avail_w - card_spacing) * 0.5f;
  float top_card_h = 320.0f;

  // --- Top row: Stats card (left) + Config card (right) ---
  ImGui::BeginChild("##StatsCard", ImVec2(card_w, top_card_h),
                    ImGuiChildFlags_Borders);
  ImGui::TextColored({0.78f, 0.10f, 0.10f, 1.0f},
                     ICON_FA_CHART_LINE " Pipeline Statistics");
  ImGui::Separator();
  stats_panel_.draw_content();
  ImGui::EndChild();

  ImGui::SameLine(0, card_spacing);

  ImGui::BeginChild("##ConfigCard", ImVec2(card_w, top_card_h),
                    ImGuiChildFlags_Borders);
  ImGui::TextColored({0.78f, 0.10f, 0.10f, 1.0f},
                     ICON_FA_SLIDERS " Configuration");
  ImGui::Separator();
  config_panel_.draw_content(config_, st);
  ImGui::EndChild();

  ImGui::Spacing();

  // --- Bottom: Threat Alerts table card ---
  float remaining_h = ImGui::GetContentRegionAvail().y;
  ImGui::BeginChild("##AlertsCard", ImVec2(-1, remaining_h),
                    ImGuiChildFlags_Borders);
  ImGui::TextColored({0.78f, 0.10f, 0.10f, 1.0f},
                     ICON_FA_SHIELD_HALVED " Threat Alerts");
  ImGui::Separator();
  alert_panel_.draw_content();
  ImGui::EndChild();
}
