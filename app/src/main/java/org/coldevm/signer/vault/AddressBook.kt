package org.coldevm.signer.vault

import android.content.Context
import org.coldevm.signer.evm.Address

/**
 * Addresses this device has signed transfers to, with a count. Used to tell a first-time recipient from a known
 * one and to flag look-alike (address-poisoning) recipients. Public data only.
 */
class AddressBook(context: Context) {
    private val prefs = context.getSharedPreferences("recipients", Context.MODE_PRIVATE)

    fun all(): Map<Address, Int> = prefs.all.mapNotNull { (k, v) ->
        val a = Address.parse(k) ?: return@mapNotNull null
        a to ((v as? Int) ?: return@mapNotNull null)
    }.toMap()

    fun remember(recipients: List<Address>) {
        if (recipients.isEmpty()) return
        val edit = prefs.edit()
        recipients.distinct().forEach { a -> edit.putInt(a.checksummed.lowercase(), prefs.getInt(a.checksummed.lowercase(), 0) + 1) }
        edit.commit()
    }

    fun clear() { prefs.edit().clear().commit() }

    val size: Int get() = prefs.all.size
}
