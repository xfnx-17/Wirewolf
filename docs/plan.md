# Plan: Add Qt GUI Alongside CLI

## Architecture Overview

The current `main.cpp` directly orchestrates the pipeline. We need to:
1. Extract the pipeline logic into a reusable `WirewolfEngine` class
2. Add a callback system so the GUI can observe events (alerts, stats, logs)
3. Build the Qt GUI on top of `WirewolfEngine`
4. Keep the CLI as a separate entry point using the same engine

## File Changes

### Phase 1: Extract Core Engine (refactor, no new dependencies)

**New: `include/wirewolf_engine.hpp`**
- `WirewolfEngine` class that owns the entire pipeline
- Methods: `start(WirewolfConfig)`, `stop()`, `is_running()`
- Callback registration: `on_alert`, `on_stats_update`, `on_log_message`, `on_state_change`
- Stats struct: `{ flows_captured, flows_filtered, flows_passed, alerts_fired, q1_size, q2_size, q1_drops, q2_drops }`

**New: `src/wirewolf_engine.cpp`**
- Extracted from current `main.cpp` pipeline wiring
- Monitor thread polls stats every second and fires `on_stats_update`
- LLM alerts route through `on_alert` callback (in addition to logging)

**Modify: `include/logger.hpp`**
- Add optional callback `on_log(LogLevel, component, message)` to Logger singleton
- GUI hooks into this to display logs in its log viewer panel
- CLI still prints to stdout/stderr as before

**Modify: `src/main.cpp`**
- Slim down to: parse config → create WirewolfEngine → engine.start() → wait for Ctrl+C → engine.stop()
- ~20 lines, delegates everything to the engine

**Modify: `include/llm_inference.hpp` / `src/llm_inference.cpp`**
- Add `std::function<void(const std::string&, const FlowData*)> alert_callback`
- When an alert fires, call the callback in addition to logging

### Phase 2: Qt GUI

**New: `gui/main_gui.cpp`** — Qt entry point (QApplication + MainWindow)

**New: `gui/mainwindow.hpp` / `gui/mainwindow.cpp`**
- Central window with a toolbar (Start/Stop/Open PCAP) and tabbed panels
- Owns `WirewolfEngine` instance
- Connects engine callbacks → Qt signals (thread-safe via `QMetaObject::invokeMethod`)

**New: `gui/dashboard_widget.hpp` / `gui/dashboard_widget.cpp`**
- Live stats: flows/sec, alerts count, filter pass rate (%), queue utilization bars
- Updates every second from engine stats callback
- Simple grid of QLabel counters + QProgressBar for queues

**New: `gui/alerts_widget.hpp` / `gui/alerts_widget.cpp`**
- QTableView backed by QStandardItemModel
- Columns: Timestamp | Source IP:Port | Dest IP:Port | Threat Type | Severity | Snippet
- Rows auto-scroll, clickable to expand full payload
- Color-coded severity (red=High, orange=Medium, yellow=Low)

**New: `gui/settings_widget.hpp` / `gui/settings_widget.cpp`**
- Form with all WirewolfConfig fields as spin boxes / line edits / checkboxes
- Interface dropdown populated from Npcap device list
- "Browse..." buttons for model paths and pcap files
- Validates config before allowing Start

**New: `gui/log_widget.hpp` / `gui/log_widget.cpp`**
- QPlainTextEdit in read-only mode with colored log lines
- Severity filter dropdown (show DEBUG/INFO/WARN/ERROR)
- Hooked to Logger's callback — displays all pipeline log output

### Phase 3: Build System

**Modify: `CMakeLists.txt`**
- New option: `option(WIREWOLF_BUILD_GUI "Build Qt GUI" OFF)`
- When ON: `find_package(Qt6 REQUIRED COMPONENTS Widgets)`
- New target: `wirewolf_gui` linking `Qt6::Widgets` + engine sources
- Core engine sources compiled into an object library shared by CLI and GUI targets

**Modify: `build.ps1`**
- New `-GUI` switch
- Sets `WIREWOLF_BUILD_GUI=ON`, auto-detects Qt6 install via `CMAKE_PREFIX_PATH`
- Copies Qt DLLs to Release directory

## Dependency

- Qt 6.x (only needed when building with `-GUI` flag)
- No impact on existing CLI build — Qt is fully optional

## Build Commands

```powershell
.\build.ps1               # CLI only (unchanged)
.\build.ps1 -GUI          # CLI + Qt GUI
.\build.ps1 -GUI -Test    # CLI + GUI + tests
```

## Thread Safety Design

The engine pipeline runs on worker threads. Qt GUI runs on the main thread.
All callbacks from engine → GUI cross thread boundaries, so:
- Engine fires `std::function` callbacks on worker threads
- MainWindow receives them and uses `QMetaObject::invokeMethod(this, [=]{ ... }, Qt::QueuedConnection)` to marshal to the Qt event loop
- This is standard Qt practice — no mutexes needed in GUI code
