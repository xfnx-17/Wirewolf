#pragma once
#include "wirewolf_types.hpp"
#include <cstddef>

class StatsPanel {
public:
  void update(const PipelineStats &stats);
  void draw();
  void draw_content();

private:
  PipelineStats stats_;

  static constexpr size_t HISTORY_SIZE = 120; // 60 seconds at 2Hz
  float filter_pass_history_[HISTORY_SIZE] = {};
  int history_offset_ = 0;
  size_t last_filter_passed_ = 0;
};
