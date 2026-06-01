package com.example.dlaauth.util

import android.util.Base64

object Base64Util {

    fun base64urlEncode(data: ByteArray): String =
        Base64.encodeToString(data, Base64.NO_WRAP or Base64.NO_PADDING)
            .replace('+', '-')
            .replace('/', '_')

    fun base64urlDecode(str: String): ByteArray {
        val standard = str.replace('-', '+').replace('_', '/')
        val padded = when (standard.length % 4) {
            2 -> "$standard=="
            3 -> "$standard="
            else -> standard
        }
        return Base64.decode(padded, Base64.NO_WRAP)
    }

    /**
     * Converts a DER/ASN.1 ECDSA signature to IEEE P1363 raw format (64 bytes).
     * DER structure: 0x30 <len> 0x02 <rlen> <r> 0x02 <slen> <s>
     */
    fun derSignatureToRaw(der: ByteArray): ByteArray {
        var offset = 0
        require(der[offset++] == 0x30.toByte()) { "Expected SEQUENCE tag 0x30" }

        // Skip total length (may be 1 or 2 bytes)
        if (der[offset].toInt() and 0x80 != 0) {
            offset += (der[offset].toInt() and 0x7F) + 1
        } else {
            offset++
        }

        fun readInteger(): ByteArray {
            require(der[offset] == 0x02.toByte()) { "Expected INTEGER tag 0x02" }
            val len = der[offset + 1].toInt() and 0xFF
            val bytes = der.copyOfRange(offset + 2, offset + 2 + len)
            return bytes
        }

        val rRaw = readInteger()
        offset += 2 + (der[offset + 1].toInt() and 0xFF)
        val sRaw = readInteger()

        fun toFixed32(b: ByteArray): ByteArray {
            // Strip leading zero sign byte if present
            val stripped = if (b.size > 32 && b[0] == 0.toByte()) b.copyOfRange(1, b.size) else b
            // Left-pad to 32 bytes
            return ByteArray(32 - stripped.size) + stripped
        }

        return toFixed32(rRaw) + toFixed32(sRaw)
    }
}