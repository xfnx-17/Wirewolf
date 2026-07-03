#pragma once
#include "wirewolf_types.hpp"
#include <string>
#include <vector>

class AlertPanel {
public:
  void add_alert(ThreatAlert alert);
  void draw();
  void draw_content();

private:
  std::vector<ThreatAlert> alerts_;
  bool auto_scroll_ = true;
  char filter_buf_[128] = "";
  int selected_index_ = -1;
  static constexpr size_t MAX_ALERTS = 10000;

  void draw_table();
  void draw_inspector();
};
