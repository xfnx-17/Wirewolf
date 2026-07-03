import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

/// Light "SOC console" palette from the Wirewolf dashboard redesign handoff.
/// Page is a cool off-white (#eef0f3); cards are pure white with soft, hue-
/// tinted shadows and a 13px corner radius. One accent blue (#2f6bff) drives
/// selection, links and the status bar. Severity uses the canonical
/// rose/orange/amber/emerald ramp.
class AppColors {
  // Surfaces
  static const background = Color(0xFFEEF0F3); // page
  static const surface = Color(0xFFFFFFFF); // cards
  static const surfaceLight = Color(0xFFF4F6F8); // table headers, input fills
  static const border = Color(0xFFE6E8EC);
  static const hairline = Color(0xFFEEF0F3); // gridlines / dividers inside cards

  // Text
  static const textPrimary = Color(0xFF1F2329);
  static const textSecondary = Color(0xFF586273);
  static const textMuted = Color(0xFF9AA1AB);

  // Severity (canonical ramp)
  static const critical = Color(0xFFF43F5E);
  static const high = Color(0xFFF97316);
  static const medium = Color(0xFFF59E0B);
  static const low = Color(0xFF10B981);
  static const info = Color(0xFF2F6BFF);

  // Accents
  static const accent = Color(0xFF2F6BFF);
  static const success = Color(0xFF10B981);
  static const warning = Color(0xFFF59E0B);
  static const error = Color(0xFFE23D57);

  // Toggle "off" track
  static const toggleOff = Color(0xFFD6DAE0);

  // Chart palette (light-friendly)
  static const chart1 = Color(0xFF2F6BFF);
  static const chart2 = Color(0xFF10B981);
  static const chart3 = Color(0xFF8B5CF6);
  static const chart4 = Color(0xFFF97316);
  static const chart5 = Color(0xFF64748B);
  static const chart6 = Color(0xFF0EA5E9);

  static Color severityColor(int level) {
    switch (level) {
      case 4: return critical;
      case 3: return high;
      case 2: return medium;
      case 1: return low;
      default: return info;
    }
  }

  static Color severityColorByName(String name) {
    switch (name.toLowerCase()) {
      case 'critical': return critical;
      case 'high': return high;
      case 'medium': return medium;
      case 'low': return low;
      default: return info;
    }
  }
}

/// Typography helpers. UI text is Inter (neutral, SOC-appropriate); all
/// numerics, IPs, ports and code use JetBrains Mono per the design.
class AppText {
  static TextStyle mono({
    double size = 11,
    Color color = AppColors.textPrimary,
    FontWeight weight = FontWeight.w500,
    double? letterSpacing,
    double? height,
  }) =>
      GoogleFonts.jetBrainsMono(
        fontSize: size,
        color: color,
        fontWeight: weight,
        letterSpacing: letterSpacing,
        height: height,
      );
}

class AppTheme {
  static ThemeData get light {
    final base = ThemeData.light(useMaterial3: true);
    return base.copyWith(
      scaffoldBackgroundColor: AppColors.background,
      colorScheme: const ColorScheme.light(
        surface: AppColors.surface,
        primary: AppColors.accent,
        secondary: AppColors.success,
        error: AppColors.error,
        onSurface: AppColors.textPrimary,
      ),
      textTheme: GoogleFonts.interTextTheme(base.textTheme).apply(
        bodyColor: AppColors.textPrimary,
        displayColor: AppColors.textPrimary,
      ),
      cardTheme: CardThemeData(
        color: AppColors.surface,
        elevation: 1.5,
        shadowColor: const Color(0x14203040),
        surfaceTintColor: Colors.transparent,
        margin: EdgeInsets.zero,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(13),
        ),
      ),
      dividerColor: AppColors.hairline,
      iconTheme: const IconThemeData(color: AppColors.textSecondary, size: 16),
      tooltipTheme: TooltipThemeData(
        waitDuration: const Duration(milliseconds: 300),
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
        decoration: BoxDecoration(
          color: const Color(0xFF1F2530),
          borderRadius: BorderRadius.circular(8),
        ),
        textStyle: const TextStyle(
          color: Colors.white,
          fontSize: 11,
          height: 1.4,
        ),
      ),
    );
  }
}
