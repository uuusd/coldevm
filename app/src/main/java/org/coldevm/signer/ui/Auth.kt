package org.coldevm.signer.ui

import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.suspendCancellableCoroutine
import javax.crypto.Cipher
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

class AuthCancelledException(message: String) : Exception(message)

/** Unlocks a Keystore-bound cipher with fingerprint or the screen-lock PIN (only the PIN when [pinOnly]). */
suspend fun FragmentActivity.authenticate(cipher: Cipher, title: String, subtitle: String? = null, pinOnly: Boolean = false): Cipher =
    suspendCancellableCoroutine { cont ->
        val prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this), object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val c = result.cryptoObject?.cipher
                if (c != null) cont.resume(c) else cont.resumeWithException(IllegalStateException("认证未返回密钥"))
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (cont.isActive) cont.resumeWithException(AuthCancelledException(errString.toString()))
            }
        })
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .apply { if (subtitle != null) setSubtitle(subtitle) }
            .setAllowedAuthenticators(if (pinOnly) DEVICE_CREDENTIAL else BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
            .setConfirmationRequired(true)
            .build()
        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
        cont.invokeOnCancellation { prompt.cancelAuthentication() }
    }
