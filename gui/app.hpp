#pragma once
#include "panels/activity_panel.hpp"
#include "panels/alert_panel.hpp"
#include "panels/config_panel.hpp"
#include "panels/log_panel.hpp"
#include "panels/stats_panel.hpp"
#include "pipeline_controller.hpp"
#include <mutex>
#include <vector>

enum class NavPage {
  Dashboard,
  Alerts,
  Activity,
  Configuration,
  Log,
};

class WirewolfApp {
public:
  WirewolfApp();
  ~WirewolfApp();

  void render();

private:
  PipelineController controller_;
  WirewolfConfig config_;

  // Panels
  AlertPanel alert_panel_;
  ActivityPanel activity_panel_;
  StatsPanel stats_panel_;
  ConfigPanel config_panel_;
  LogPanel log_panel_;

  // Thread-safe buffers (pipeline threads push, render thread reads)
  std::mutex alerts_mutex_;
  std::vector<ThreatAlert> pending_alerts_;

  std::mutex stats_mutex_;
  PipelineStats latest_stats_;

  std::mutex activity_mutex_;
  std::vector<FlowEvent> pending_activity_;

  std::mutex logs_mutex_;
  struct LogEntry {
    int level;
    std::string component;
    std::string message;
  };
  std::vector<LogEntry> pending_logs_;

  PipelineState current_state_ = PipelineState::Stopped;
  std::mutex state_mutex_;

  NavPage current_page_ = NavPage::Dashboard;

  void setup_callbacks();
  void process_pending_data();
  void draw_sidebar(PipelineState st);
  void draw_content(PipelineState st);
  void draw_dashboard(PipelineState st);
};
