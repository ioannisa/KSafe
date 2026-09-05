package eu.anifantakis.lib.ksafe.internal.keyvault

import eu.anifantakis.lib.ksafe.internal.KSafeEngineMessage

/**
 * [KSafeEngineMessage.VAULT_UNAVAILABLE] is a protocol the core's classifier matches on: a vault
 * that respells it makes the orphan sweep read an outage as an absent key, destroying data.
 */
internal fun vaultUnavailable(
    alias: String,
    failure: String,
    reason: String,
    cause: Throwable? = null,
): IllegalStateException =
    IllegalStateException(
        "KSafe: key ${KSafeEngineMessage.VAULT_UNAVAILABLE} — $failure for alias \"$alias\" ($reason).",
        cause,
    )
