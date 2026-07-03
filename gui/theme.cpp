#include "theme.hpp"
#include "imgui.h"

void ApplyRedTeamCTFTheme() {
  ImGuiStyle &style = ImGui::GetStyle();

  // --- Geometry: Card look ---
  style.WindowRounding = 8.0f;
  style.ChildRounding = 8.0f;
  style.PopupRounding = 8.0f;
  style.FrameRounding = 4.0f;
  style.GrabRounding = 4.0f;
  style.TabRounding = 4.0f;
  style.ScrollbarRounding = 6.0f;

  style.WindowPadding = {12, 12};
  style.FramePadding = {8, 4};
  style.CellPadding = {6, 3};
  style.ItemSpacing = {8, 8};
  style.ItemInnerSpacing = {6, 4};
  style.ScrollbarSize = 12.0f;
  style.GrabMinSize = 10.0f;
  style.WindowBorderSize = 1.0f;
  style.ChildBorderSize = 1.0f;
  style.PopupBorderSize = 1.0f;
  style.FrameBorderSize = 0.0f;

  // --- Colors: Pitch black + Crimson Red ---
  ImVec4 *c = style.Colors;

  // Text
  c[ImGuiCol_Text] = {0.88f, 0.88f, 0.88f, 1.00f};
  c[ImGuiCol_TextDisabled] = {0.40f, 0.40f, 0.40f, 1.00f};

  // Backgrounds — pitch black
  c[ImGuiCol_WindowBg] = {0.04f, 0.04f, 0.04f, 1.00f}; // #0A0A0A
  c[ImGuiCol_ChildBg] = {0.07f, 0.07f, 0.07f, 1.00f};  // #121212
  c[ImGuiCol_PopupBg] = {0.07f, 0.07f, 0.07f, 1.00f};

  // Borders — subtle dark
  c[ImGuiCol_Border] = {0.18f, 0.18f, 0.18f, 1.00f};
  c[ImGuiCol_BorderShadow] = {0.00f, 0.00f, 0.00f, 0.00f};

  // Frame backgrounds (inputs, dropdowns)
  c[ImGuiCol_FrameBg] = {0.10f, 0.10f, 0.10f, 1.00f};        // #1A1A1A
  c[ImGuiCol_FrameBgHovered] = {0.55f, 0.10f, 0.10f, 0.60f};  // Crimson hover
  c[ImGuiCol_FrameBgActive] = {0.63f, 0.10f, 0.10f, 0.80f};   // Crimson active

  // Title bars
  c[ImGuiCol_TitleBg] = {0.04f, 0.04f, 0.04f, 1.00f};
  c[ImGuiCol_TitleBgActive] = {0.55f, 0.10f, 0.10f, 1.00f};   // #8C1919
  c[ImGuiCol_TitleBgCollapsed] = {0.04f, 0.04f, 0.04f, 0.75f};

  // Menu bar
  c[ImGuiCol_MenuBarBg] = {0.06f, 0.06f, 0.06f, 1.00f};

  // Scrollbar
  c[ImGuiCol_ScrollbarBg] = {0.04f, 0.04f, 0.04f, 0.60f};
  c[ImGuiCol_ScrollbarGrab] = {0.20f, 0.20f, 0.20f, 1.00f};
  c[ImGuiCol_ScrollbarGrabHovered] = {0.55f, 0.10f, 0.10f, 1.00f};
  c[ImGuiCol_ScrollbarGrabActive] = {0.78f, 0.10f, 0.10f, 1.00f};

  // Buttons — Crimson Red
  c[ImGuiCol_Button] = {0.55f, 0.10f, 0.10f, 1.00f};          // #8C1919
  c[ImGuiCol_ButtonHovered] = {0.63f, 0.10f, 0.10f, 1.00f};   // #A01919
  c[ImGuiCol_ButtonActive] = {0.78f, 0.10f, 0.10f, 1.00f};    // #C81919

  // Headers (table selections, collapsing headers)
  c[ImGuiCol_Header] = {0.55f, 0.10f, 0.10f, 0.50f};
  c[ImGuiCol_HeaderHovered] = {0.63f, 0.10f, 0.10f, 0.70f};
  c[ImGuiCol_HeaderActive] = {0.78f, 0.10f, 0.10f, 1.00f};

  // Separator
  c[ImGuiCol_Separator] = {0.17f, 0.17f, 0.17f, 1.00f};
  c[ImGuiCol_SeparatorHovered] = {0.55f, 0.10f, 0.10f, 1.00f};
  c[ImGuiCol_SeparatorActive] = {0.78f, 0.10f, 0.10f, 1.00f};

  // Resize grip
  c[ImGuiCol_ResizeGrip] = {0.55f, 0.10f, 0.10f, 0.25f};
  c[ImGuiCol_ResizeGripHovered] = {0.55f, 0.10f, 0.10f, 0.67f};
  c[ImGuiCol_ResizeGripActive] = {0.78f, 0.10f, 0.10f, 1.00f};

  // Tabs
  c[ImGuiCol_Tab] = {0.10f, 0.10f, 0.10f, 1.00f};
  c[ImGuiCol_TabHovered] = {0.55f, 0.10f, 0.10f, 0.80f};
  c[ImGuiCol_TabSelected] = {0.55f, 0.10f, 0.10f, 1.00f};
  c[ImGuiCol_TabDimmed] = {0.07f, 0.07f, 0.07f, 1.00f};
  c[ImGuiCol_TabDimmedSelected] = {0.35f, 0.08f, 0.08f, 1.00f};

  // Check, slider, grab
  c[ImGuiCol_CheckMark] = {0.78f, 0.10f, 0.10f, 1.00f};       // #C81919
  c[ImGuiCol_SliderGrab] = {0.55f, 0.10f, 0.10f, 1.00f};
  c[ImGuiCol_SliderGrabActive] = {0.78f, 0.10f, 0.10f, 1.00f};

  // Table
  c[ImGuiCol_TableHeaderBg] = {0.10f, 0.10f, 0.10f, 1.00f};
  c[ImGuiCol_TableBorderStrong] = {0.18f, 0.18f, 0.18f, 1.00f};
  c[ImGuiCol_TableBorderLight] = {0.13f, 0.13f, 0.13f, 1.00f};
  c[ImGuiCol_TableRowBg] = {0.00f, 0.00f, 0.00f, 0.00f};
  c[ImGuiCol_TableRowBgAlt] = {0.06f, 0.06f, 0.06f, 1.00f};

  // Nav / selection
  c[ImGuiCol_NavHighlight] = {0.78f, 0.10f, 0.10f, 1.00f};
  c[ImGuiCol_TextSelectedBg] = {0.55f, 0.10f, 0.10f, 0.35f};

  // Misc
  c[ImGuiCol_DragDropTarget] = {0.78f, 0.10f, 0.10f, 0.90f};
  c[ImGuiCol_PlotLines] = {0.78f, 0.10f, 0.10f, 1.00f};
  c[ImGuiCol_PlotLinesHovered] = {1.00f, 0.20f, 0.20f, 1.00f};
  c[ImGuiCol_PlotHistogram] = {0.78f, 0.10f, 0.10f, 1.00f};
  c[ImGuiCol_PlotHistogramHovered] = {1.00f, 0.20f, 0.20f, 1.00f};
}
