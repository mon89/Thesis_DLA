package com.example.dlaauth.service

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Log
import com.example.dlaauth.util.Base64Util
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

enum class KeyBackingLevel {
    STRONGBOX,  // Dedicated secure chip (best)
    TEE,        // Trusted Execution Environment
    SOFTWARE,   // Software only (NOT secure)
    NOT_FOUND,  // Key doesn't exist
    UNKNOWN;    // Error during verification

    fun displayName(): String = when (this) {
        STRONGBOX -> "StrongBox (hardware chip)"
        TEE       -> "TEE (secure CPU)"
        SOFTWARE  -> "Software (insecure)"
        NOT_FOUND -> "Not created"
        UNKNOWN   -> "Unknown"
    }

    fun isSecure(): Boolean = this == STRONGBOX || this == TEE
}

class KeyStoreDBKService {

    private companion object {
        const val KEY_ALIAS = "com.example.dlaauth.dbk"
        const val TAG = "DBK"
    }

    fun getOrCreateKeyPair(context: Context): KeyPair {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }

        if (keyStore.containsAlias(KEY_ALIAS)) {
            Log.d(TAG, "Key exists — loading from AndroidKeyStore (alias=$KEY_ALIAS)")
            val privateKey = keyStore.getKey(KEY_ALIAS, null) as java.security.PrivateKey
            val publicKey = keyStore.getCertificate(KEY_ALIAS).publicKey
            Log.d(TAG, "Key loaded: algorithm=${privateKey.algorithm} format=${privateKey.format}")
            return KeyPair(publicKey, privateKey)
        }

        Log.d(TAG, "No existing key — generating new EC P-256 key pair (alias=$KEY_ALIAS)")
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
        )

        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setUserAuthenticationRequired(false)

        try {
            builder.setIsStrongBoxBacked(true)
            keyPairGenerator.initialize(builder.build())
            Log.d(TAG, "Key generator initialized with StrongBox backing")
            val t0 = System.nanoTime()
            val keyPair = keyPairGenerator.generateKeyPair()
            Log.d(TAG, "generateKeyPair (StrongBox): ${(System.nanoTime() - t0) / 1_000_000}ms")
            return keyPair
        } catch (e: Exception) {
            Log.w(TAG, "StrongBox key generation failed (${e.message}) — falling back to TEE")
        }

        builder.setIsStrongBoxBacked(false)
        keyPairGenerator.initialize(builder.build())
        Log.d(TAG, "Key generator initialized with TEE backing")
        val t0 = System.nanoTime()
        val keyPair = keyPairGenerator.generateKeyPair()
        Log.d(TAG, "generateKeyPair (TEE): ${(System.nanoTime() - t0) / 1_000_000}ms")
        return keyPair
    }

    fun getPublicKeyJWK(context: Context): Map<String, String> {
        val keyPair = getOrCreateKeyPair(context)
        val ecPublicKey = keyPair.public as ECPublicKey
        val w = ecPublicKey.w

        fun bigIntToFixed32(n: BigInteger): ByteArray {
            val bytes = n.toByteArray()
            // Strip leading zero sign byte if present
            val stripped = if (bytes.size > 32 && bytes[0] == 0.toByte()) bytes.copyOfRange(1, bytes.size) else bytes
            // Left-pad to 32 bytes if shorter
            return ByteArray(32 - stripped.size) + stripped
        }

        val x = Base64Util.base64urlEncode(bigIntToFixed32(w.affineX))
        val y = Base64Util.base64urlEncode(bigIntToFixed32(w.affineY))

        return mapOf("kty" to "EC", "crv" to "P-256", "x" to x, "y" to y)
    }

    fun sign(challengeBase64url: String, context: Context): String {
        val challengeBytes = Base64Util.base64urlDecode(challengeBase64url)
        Log.d(TAG, "Signing challenge: ${challengeBase64url.take(16)}… (${challengeBytes.size} bytes raw)")

        val keyStore = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
        val privateKey = keyStore.getKey(KEY_ALIAS, null) as java.security.PrivateKey
        Log.d(TAG, "Private key retrieved from AndroidKeyStore (algorithm=${privateKey.algorithm})")

        val signature = Signature.getInstance("SHA256withECDSA")
        val initStart = System.nanoTime()
        signature.initSign(privateKey)
        val initMs = (System.nanoTime() - initStart) / 1_000_000.0
        signature.update(challengeBytes)
        val signStart = System.nanoTime()
        val derSig = signature.sign()
        val signMs = (System.nanoTime() - signStart) / 1_000_000.0
        val elapsedMs = initMs + signMs

        Log.d(TAG, "sign() — initSign: ${initMs.toLong()}ms  Signature.sign(): ${signMs.toLong()}ms  total: ${elapsedMs.toLong()}ms")

        val rawSig = Base64Util.derSignatureToRaw(derSig)
        val encoded = Base64Util.base64urlEncode(rawSig)
        Log.d(TAG, "Raw signature: ${rawSig.size} bytes — base64url: ${encoded.take(16)}…")
        return encoded
    }

    fun deleteKey() {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
        keyStore.deleteEntry(KEY_ALIAS)
    }

    fun keyExists(): Boolean {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
        return keyStore.containsAlias(KEY_ALIAS)
    }

    fun verifyKeyBackingLevel(): KeyBackingLevel {
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            val privateKey = keyStore.getKey(KEY_ALIAS, null) as? PrivateKey
                ?: return KeyBackingLevel.NOT_FOUND

            val factory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
            val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java)

            val level = when {
                !keyInfo.isInsideSecureHardware -> KeyBackingLevel.SOFTWARE
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
                    keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX ->
                    KeyBackingLevel.STRONGBOX
                else -> KeyBackingLevel.TEE
            }

            return level
        } catch (e: Exception) {
            Log.e(TAG, "Failed to verify key backing: ${e.message}")
            return KeyBackingLevel.UNKNOWN
        }
    }
}