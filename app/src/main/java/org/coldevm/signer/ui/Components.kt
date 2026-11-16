package org.coldevm.signer.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.TextUnit
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.coldevm.signer.evm.Risk

val Green = Color(0xFF3DDC97)
val Purple = Color(0xFF8FA8FF)
val WarnColor = Color(0xFFFFB020)
val DangerColor = Color(0xFFFF5252)

@Composable
fun ColdEvmTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = Green, onPrimary = Color.Black,
            secondary = Purple,
            background = Color(0xFF101418), surface = Color(0xFF101418),
            surfaceVariant = Color(0xFF1C2228),
            error = DangerColor,
        ),
        content = content,
    )
}

/**
 * Scrollable page with a top bar: back arrow, title and optional action icons. Tab pages pass
 * [bottomInset] = false because the navigation bar below them already pads for the system bar.
 * [bottomBar] stays fixed below the scrolling content, e.g. the sign / reject buttons.
 */
@Composable
fun Page(
    title: String,
    onBack: (() -> Unit)? = null,
    bottomInset: Boolean = true,
    actions: @Composable RowScope.() -> Unit = {},
    bottomBar: @Composable ColumnScope.() -> Unit = {},
    content: @Composable ColumnScope.() -> Unit,
) {
    val insets = if (bottomInset) WindowInsets.safeDrawing else WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal)
    Column(Modifier.fillMaxSize().windowInsetsPadding(insets).imePadding()) {
        Row(Modifier.fillMaxWidth().height(56.dp).padding(horizontal = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            if (onBack != null) IconButton(onClick = onBack) { Icon(ColdIcons.Back, contentDescription = "返回") }
            Text(
                title,
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f).padding(start = if (onBack == null) 12.dp else 4.dp),
            )
            actions()
        }
        Column(
            Modifier.fillMaxWidth().weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            content()
            Spacer(Modifier.height(24.dp))
        }
        bottomBar()
    }
}

/** Round badge with the wallet's initial, coloured from its fingerprint so wallets are told apart at a glance. */
@Composable
fun WalletAvatar(name: String, fingerprint: ByteArray, size: Dp = 44.dp) {
    val hue = ((fingerprint[0].toInt() and 0xff) shl 8 or (fingerprint[1].toInt() and 0xff)) % 360
    Box(
        Modifier.size(size).clip(CircleShape).background(Color.hsv(hue.toFloat(), 0.45f, 0.85f)),
        contentAlignment = Alignment.Center,
    ) {
        Text(name.trim().take(1).ifEmpty { "?" }, color = Color.Black, fontWeight = FontWeight.Bold, fontSize = (size.value * 0.42f).sp)
    }
}

/** A tappable list row: leading content, title + subtitle, and a chevron. */
@Composable
fun ListRow(title: String, subtitle: String? = null, monoSubtitle: Boolean = false, onClick: () -> Unit, leading: @Composable () -> Unit = {}) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 14.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        leading()
        Column(Modifier.weight(1f)) {
            Text(title, fontWeight = FontWeight.SemiBold)
            if (subtitle != null) Text(subtitle, style = MaterialTheme.typography.bodySmall, fontFamily = if (monoSubtitle) FontFamily.Monospace else null,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f))
        }
        Icon(ColdIcons.Chevron, contentDescription = null, tint = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.4f))
    }
}

/** Card that groups rows edge to edge, like a settings list. */
@Composable
fun ListCard(content: @Composable ColumnScope.() -> Unit) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant), modifier = Modifier.fillMaxWidth()) {
        Column(content = content)
    }
}

fun shortAddress(address: String) = "${address.take(8)}…${address.takeLast(6)}"

@Composable
fun InfoCard(color: Color = MaterialTheme.colorScheme.surfaceVariant, content: @Composable ColumnScope.() -> Unit) {
    Card(colors = CardDefaults.cardColors(containerColor = color), modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp), content = content)
    }
}

@Composable
fun Banner(risk: Risk, text: String) {
    val c = when (risk) { Risk.DANGER -> DangerColor; Risk.WARN -> WarnColor; Risk.INFO -> Green }
    InfoCard(color = c.copy(alpha = 0.15f)) {
        Text(text, color = c, fontWeight = FontWeight.Medium)
    }
}

private val ADDRESS = Regex("0x[0-9a-fA-F]{40}(?![0-9a-fA-F])")

/**
 * Splits 0x addresses into groups of four and emphasises the first and last group, which is
 * what address-poisoning attacks try to imitate, so the whole address gets compared.
 */
fun formatAddresses(text: String, edge: Color): AnnotatedString = buildAnnotatedString {
    var last = 0
    for (m in ADDRESS.findAll(text)) {
        append(text.substring(last, m.range.first))
        append("0x ")
        val groups = m.value.substring(2).chunked(4)
        groups.forEachIndexed { i, g ->
            if (i > 0) append(' ')
            if (i == 0 || i == groups.lastIndex) withStyle(SpanStyle(color = edge, fontWeight = FontWeight.Bold)) { append(g) } else append(g)
        }
        last = m.range.last + 1
    }
    append(text.substring(last))
}

@Composable
fun Mono(text: String, highlight: Boolean = false, groupAddresses: Boolean = true, fontSize: TextUnit = 14.sp, highlightColor: Color = Green) {
    val hasAddress = groupAddresses && ADDRESS.containsMatchIn(text)
    Text(
        if (groupAddresses) formatAddresses(text, if (highlight) highlightColor else Purple) else AnnotatedString(text),
        fontFamily = FontFamily.Monospace,
        fontSize = fontSize,
        // Addresses keep a neutral body so the coloured first/last groups stand out.
        color = if (highlight && !hasAddress) highlightColor else MaterialTheme.colorScheme.onSurface,
        fontWeight = if (highlight) FontWeight.Bold else FontWeight.Normal,
    )
}

@Composable
fun Label(text: String) {
    Text(text, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f))
}
