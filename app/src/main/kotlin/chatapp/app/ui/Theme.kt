package chatapp.app.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

/** Phase 5 — single dark theme (MVP); no dynamic colors (zero extra deps). */
@Composable
fun ChatAppTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = darkColorScheme(), content = content)
}
