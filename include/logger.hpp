#pragma once
#include <chrono>
#include <functional>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>

// Windows headers define ERROR as a macro — temporarily remove it
#ifdef ERROR
#pragma push_macro("ERROR")
#undef ERROR
#define WIREWOLF_LOGGER_RESTORE_ERROR
#endif

enum class LogLevel { DEBUG = 0, INFO = 1, WARN = 2, ERROR = 3 };

class Logger {
public:
  static Logger &instance() {
    static Logger logger;
    return logger;
  }

  using LogCallback =
      std::function<void(LogLevel, const std::string &, const std::string &)>;

  void set_level(LogLevel level) { min_level = level; }
  void set_level(int level) { min_level = static_cast<LogLevel>(level); }

  void set_callback(LogCallback cb) {
    std::lock_guard<std::mutex> lock(mtx);
    callback_ = std::move(cb);
  }

  void log(LogLevel level, const std::string &component,
           const std::string &message) {
    if (level < min_level)
      return;

    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  now.time_since_epoch()) %
              1000;

    std::tm tm_buf{};
#ifdef _WIN32
    localtime_s(&tm_buf, &time_t);
#else
    localtime_r(&time_t, &tm_buf);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%H:%M:%S") << "." << std::setfill('0')
        << std::setw(3) << ms.count() << " [" << level_str(level) << "] ["
        << component << "] " << message << "\n";

    std::lock_guard<std::mutex> lock(mtx);
    if (level >= LogLevel::WARN) {
      std::cerr << oss.str() << std::flush;
    } else {
      std::cout << oss.str() << std::flush;
    }
    if (callback_) {
      callback_(level, component, message);
    }
  }

  void debug(const std::string &component, const std::string &msg) {
    log(LogLevel::DEBUG, component, msg);
  }
  void info(const std::string &component, const std::string &msg) {
    log(LogLevel::INFO, component, msg);
  }
  void warn(const std::string &component, const std::string &msg) {
    log(LogLevel::WARN, component, msg);
  }
  void error(const std::string &component, const std::string &msg) {
    log(LogLevel::ERROR, component, msg);
  }

private:
  Logger() = default;
  LogLevel min_level = LogLevel::INFO;
  std::mutex mtx;
  LogCallback callback_;

  static const char *level_str(LogLevel level) {
    switch (level) {
    case LogLevel::DEBUG:
      return "DEBUG";
    case LogLevel::INFO:
      return " INFO";
    case LogLevel::WARN:
      return " WARN";
    case LogLevel::ERROR:
      return "ERROR";
    }
    return "?????";
  }
};

#define LOG_DEBUG(comp, msg) Logger::instance().debug(comp, msg)
#define LOG_INFO(comp, msg) Logger::instance().info(comp, msg)
#define LOG_WARN(comp, msg) Logger::instance().warn(comp, msg)
#define LOG_ERROR(comp, msg) Logger::instance().error(comp, msg)

#ifdef WIREWOLF_LOGGER_RESTORE_ERROR
#pragma pop_macro("ERROR")
#undef WIREWOLF_LOGGER_RESTORE_ERROR
#endif
