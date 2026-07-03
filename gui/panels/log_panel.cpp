#include "log_panel.hpp"
#include "IconsFontAwesome6.h"
#include "imgui.h"
#include <cstring>

static const char *level_name(int level) {
  switch (level) {
  case 0:
    return "DEBUG";
  case 1:
    return "INFO";
  case 2:
    return "WARN";
  case 3:
    return "ERROR";
  default:
    return "?";
  }
}

static ImVec4 level_color(int level) {
  switch (level) {
  case 0:
    return {0.5f, 0.5f, 0.5f, 1.0f}; // DEBUG: gray
  case 1:
    return {0.9f, 0.9f, 0.9f, 1.0f}; // INFO: white
  case 2:
    return {1.0f, 0.8f, 0.0f, 1.0f}; // WARN: yellow
  case 3:
    return {1.0f, 0.3f, 0.3f, 1.0f}; // ERROR: red
  default:
    return {1.0f, 1.0f, 1.0f, 1.0f};
  }
}

void LogPanel::add_entry(int level, const std::string &component,
                         const std::string &message) {
  Entry e;
  e.level = level;
  e.component = component;
  e.message = message;
  e.formatted =
      std::string("[") + level_name(level) + "] [" + component + "] " + message;
  entries_.push_back(std::move(e));

  if (entries_.size() > MAX_ENTRIES) {
    entries_.erase(entries_.begin(),
                   entries_.begin() + (entries_.size() - MAX_ENTRIES));
  }
}

void LogPanel::clear() { entries_.clear(); }

void LogPanel::draw() {
  ImGui::Begin(ICON_FA_TERMINAL " Log");
  draw_content();
  ImGui::End();
}

void LogPanel::draw_content() {
  // Toolbar
  const char *level_names[] = {"All", "INFO+", "WARN+", "ERROR"};
  ImGui::SetNextItemWidth(80);
  ImGui::Combo("##level", &min_level_, level_names, 4);
  ImGui::SameLine();
  ImGui::InputTextWithHint("##logfilter", "Filter...", filter_text_,
                           sizeof(filter_text_));
  ImGui::SameLine();
  ImGui::Checkbox("Auto-scroll", &auto_scroll_);
  ImGui::SameLine();
  if (ImGui::Button("Clear")) {
    clear();
  }
  ImGui::SameLine();
  ImGui::Text("(%zu lines)", entries_.size());

  ImGui::Separator();

  ImGui::BeginChild("LogScroll", ImVec2(0, 0), ImGuiChildFlags_None,
                    ImGuiWindowFlags_HorizontalScrollbar);

  bool has_filter = filter_text_[0] != '\0';

  ImGuiListClipper clipper;
  clipper.Begin((int)entries_.size());
  while (clipper.Step()) {
    for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
      const auto &entry = entries_[i];

      // Level filter
      if (entry.level < min_level_)
        continue;

      // Text filter
      if (has_filter && !strstr(entry.formatted.c_str(), filter_text_))
        continue;

      ImGui::PushStyleColor(ImGuiCol_Text, level_color(entry.level));
      ImGui::TextUnformatted(entry.formatted.c_str());
      ImGui::PopStyleColor();
    }
  }

  if (auto_scroll_ && ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
    ImGui::SetScrollHereY(1.0f);

  ImGui::EndChild();
}
