include(FetchContent)

# --- Dear ImGui ---
FetchContent_Declare(
    imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG        docking
)
FetchContent_MakeAvailable(imgui)

add_library(imgui_lib STATIC
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_demo.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp
)

target_include_directories(imgui_lib PUBLIC
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends
)

target_link_libraries(imgui_lib PUBLIC d3d11 dxgi d3dcompiler)

# --- wirewolf_gui executable ---
add_executable(wirewolf_gui WIN32
    main_gui.cpp
    app.cpp
    theme.cpp
    panels/alert_panel.cpp
    panels/activity_panel.cpp
    panels/stats_panel.cpp
    panels/config_panel.cpp
    panels/log_panel.cpp
)

target_include_directories(wirewolf_gui PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/fonts
)

target_link_libraries(wirewolf_gui PRIVATE
    wirewolf_core
    imgui_lib
)

# Copy font files next to the executable
file(GLOB WIREWOLF_FONT_FILES "${CMAKE_CURRENT_SOURCE_DIR}/fonts/*.ttf")
foreach(font ${WIREWOLF_FONT_FILES})
    add_custom_command(TARGET wirewolf_gui POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${font}" "$<TARGET_FILE_DIR:wirewolf_gui>"
    )
endforeach()
