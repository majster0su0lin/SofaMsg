package com.sofamsg.app.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

/**
 * SofaMsg Material 3 Theme
 *
 * Design philosophy:
 *   • **Always dark** — a privacy-focused messenger should default to
 *     dark mode to reduce visual attention and screen-peeking risk.
 *   • **Neutral palette** — avoid bright, attention-grabbing colors.
 *     The app should look like any other messaging app, not stand out.
 *   • **Dynamic color on Android 12+** — respects system wallpaper
 *     colors when available, falling back to our custom dark scheme.
 */

// ── Custom dark color scheme ──
// Used on Android < 12 where dynamic colors aren't available.
// Muted blue-grey palette — professional, unremarkable.
private val DarkColorScheme = darkColorScheme(
    primary = Color(0xFF8AB4F8),           // Soft blue — primary actions
    onPrimary = Color(0xFF003062),         // Dark blue text on primary
    primaryContainer = Color(0xFF004A8F),  // Button backgrounds
    onPrimaryContainer = Color(0xFFD3E4FF),

    secondary = Color(0xFF9ECAFF),         // Lighter blue — secondary actions
    onSecondary = Color(0xFF003258),
    secondaryContainer = Color(0xFF00497D),
    onSecondaryContainer = Color(0xFFCFE5FF),

    tertiary = Color(0xFFBBC7DB),          // Grey-blue — tertiary elements
    onTertiary = Color(0xFF253140),
    tertiaryContainer = Color(0xFF3C4858),
    onTertiaryContainer = Color(0xFFD7E3F8),

    background = Color(0xFF1A1C1E),        // Near-black background
    onBackground = Color(0xFFE2E2E6),
    surface = Color(0xFF1A1C1E),
    onSurface = Color(0xFFE2E2E6),

    surfaceVariant = Color(0xFF43474E),    // Card / bubble backgrounds
    onSurfaceVariant = Color(0xFFC3C6CF),

    outline = Color(0xFF8D9199),
    outlineVariant = Color(0xFF43474E),

    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
)

@Composable
fun SofaMsgTheme(
    darkTheme: Boolean = true,  // Always dark by default
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        // Use dynamic colors (wallpaper-based) on Android 12+
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context)
            else dynamicLightColorScheme(context)
        }
        // Fall back to our custom dark palette
        else -> DarkColorScheme
    }

    // Make the status bar and navigation bar match our theme
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = colorScheme.surface.toArgb()
            window.navigationBarColor = colorScheme.surface.toArgb()
            val insetsController = WindowCompat.getInsetsController(window, view)
            insetsController.isAppearanceLightStatusBars = !darkTheme
            insetsController.isAppearanceLightNavigationBars = !darkTheme
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography(),  // Use Material 3 default typography
        content = content
    )
}
