#pragma once
#include "wirewolf_types.hpp"
#include <cstddef>
#include <vector>

class ActivityPanel {
public:
  void add_event(FlowEvent event);
  void draw();
  void draw_content();
  void clear();

private:
  std::vector<FlowEvent> events_;
  bool auto_scroll_ = true;
  char filter_buf_[128] = "";
  static constexpr size_t MAX_EVENTS = 5000;

  void draw_table();
};
