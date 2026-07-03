#pragma once
#include <cstddef>
#include <string>
#include <vector>

class LogPanel {
public:
  void add_entry(int level, const std::string &component,
                 const std::string &message);
  void draw();
  void draw_content();
  void clear();

private:
  struct Entry {
    int level;
    std::string component;
    std::string message;
    std::string formatted;
  };

  std::vector<Entry> entries_;
  int min_level_ = 0;
  bool auto_scroll_ = true;
  char filter_text_[256] = "";
  static constexpr size_t MAX_ENTRIES = 50000;
};
