package net.mullvad.mullvadvpn.lib.ui.component

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import net.mullvad.mullvadvpn.lib.common.compose.createCopyToClipboardHandle
import net.mullvad.mullvadvpn.lib.ui.resource.R

@Composable
fun CopyableLink(url: String, modifier: Modifier = Modifier) {
    val copyToClipboard = createCopyToClipboardHandle(isSensitive = true)
    Column(modifier = modifier) {
        Text(
            text = stringResource(R.string.browser_unavailable),
            color = MaterialTheme.colorScheme.onSurface,
        )
        SelectionContainer {
            Text(text = url, color = MaterialTheme.colorScheme.onSurface)
        }
        TextButton(onClick = { copyToClipboard(url, null) }) {
            Text(text = stringResource(R.string.copy))
        }
    }
}
