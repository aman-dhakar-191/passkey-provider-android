package io.github.amandhakar.passkey.recovery

import android.graphics.Paint
import android.graphics.Rect
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import io.github.amandhakar.passkey.transfer.QrCode
import java.io.ByteArrayOutputStream
import java.text.DateFormat
import java.util.Date

/**
 * The printable card for a key piece: an A4 PDF with the piece as a QR code (scanned when restoring or
 * checking) and as text (in case the QR code is damaged). Printing it is up to the person; the app never keeps
 * the PDF.
 */
internal object ShareCard {
    private const val WIDTH = 595 // A4 in PDF points
    private const val HEIGHT = 842
    private const val MARGIN = 48

    fun pdf(share: RecoveryShare, createdAt: Long): ByteArray {
        val document = PdfDocument()
        try {
            val page = document.startPage(PdfDocument.PageInfo.Builder(WIDTH, HEIGHT, 1).create())
            val canvas = page.canvas
            val title = Paint().apply { textSize = 22f; typeface = Typeface.DEFAULT_BOLD; isAntiAlias = true }
            val body = Paint().apply { textSize = 11f; isAntiAlias = true }
            val mono = Paint().apply { textSize = 12f; typeface = Typeface.MONOSPACE; isAntiAlias = true }
            var y = MARGIN + 22f

            canvas.drawText("Passkey Vault backup key piece", MARGIN.toFloat(), y, title)
            y += 22f
            canvas.drawText(
                "Piece ${share.x} · made ${DateFormat.getDateInstance(DateFormat.LONG).format(Date(createdAt))}",
                MARGIN.toFloat(), y, body,
            )
            y += 20f

            val qrSize = 300
            val qr = QrCode.bitmap(share.qr(), qrSize)
            val left = (WIDTH - qrSize) / 2
            canvas.drawBitmap(qr, null, Rect(left, y.toInt(), left + qrSize, y.toInt() + qrSize), null)
            qr.recycle()
            y += qrSize + 24f

            share.text().chunked(4 * 5 + 5).forEach { line ->
                canvas.drawText(line.trimEnd('-'), MARGIN.toFloat(), y, mono)
                y += 18f
            }
            y += 12f

            listOf(
                "This card is one of several pieces of the key to your encrypted passkey backup.",
                "One piece alone can't open anything. Any two pieces together can, so keep this",
                "card apart from the other keepers.",
                "",
                "Keep it at home, on paper. Don't photograph it, don't put it in Google Photos,",
                "Drive or e-mail: that would give Google a second piece.",
                "",
                "To restore on a new phone: Passkey Vault → ⋮ → Backup & recovery → Restore,",
                "then scan this card. Check it every few months the same way (Check card).",
            ).forEach { line ->
                canvas.drawText(line, MARGIN.toFloat(), y, body)
                y += 16f
            }
            document.finishPage(page)
            return ByteArrayOutputStream().also { document.writeTo(it) }.toByteArray()
        } finally {
            document.close()
        }
    }
}
