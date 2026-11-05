package net.mullvad.mullvadvpn.feature.home.impl.connect

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.tooling.preview.Preview
import androidx.lifecycle.compose.dropUnlessResumed
import net.mullvad.mullvadvpn.core.Navigator
import net.mullvad.mullvadvpn.lib.common.compose.clickableAnnotatedString
import net.mullvad.mullvadvpn.lib.common.compose.createCopyToClipboardHandle
import net.mullvad.mullvadvpn.lib.common.compose.safeOpenUri
import net.mullvad.mullvadvpn.lib.ui.component.dialog.InfoDialog
import net.mullvad.mullvadvpn.lib.ui.resource.R
import net.mullvad.mullvadvpn.lib.ui.theme.AppTheme

@Preview
@Composable
private fun PreviewAndroid16UpgradeWarningInfoDialog() {
    AppTheme { Android16UpgradeWarningInfoDialog(onDismiss = {}, onClickSupport = {}) }
}

@Composable
fun Android16UpgradeWarningInfo(navigator: Navigator) {
    val copyToClipboard = createCopyToClipboardHandle(isSensitive = false)
    val uriHandler = LocalUriHandler.current
    Android16UpgradeWarningInfoDialog(
        onDismiss = dropUnlessResumed { navigator.goBack() },
        onClickSupport = { url ->
            uriHandler.safeOpenUri(url).onLeft { copyToClipboard(url, null) }
        },
    )
}

@Composable
fun Android16UpgradeWarningInfoDialog(onDismiss: () -> Unit, onClickSupport: (String) -> Unit) {
    InfoDialog(
        title = stringResource(id = R.string.android_16_upgrade_warning_title),
        message = stringResource(id = R.string.android_16_upgrade_warning_dialog_first_message),
        additionalInfo =
            clickableAnnotatedString(
                text = stringResource(R.string.android_16_upgrade_warning_support_message),
                linkStyle =
                    SpanStyle(
                        color = MaterialTheme.colorScheme.onSurface,
                        textDecoration = TextDecoration.Underline,
                    ),
                argument = stringResource(R.string.github_issues_url),
                onClick = onClickSupport,
            ),
        showIcon = false,
        onDismiss = onDismiss,
    )
}
