#pragma once
#include "config.hpp"
#include "pipeline_controller.hpp"
#include "wirewolf_types.hpp"
#include <vector>

class ConfigPanel {
public:
  void draw(WirewolfConfig &config, PipelineState state);
  void draw_content(WirewolfConfig &config, PipelineState state);

private:
  std::vector<PipelineController::InterfaceInfo> interfaces_;
  int selected_interface_ = -1;
  bool interfaces_loaded_ = false;
};
