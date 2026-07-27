package eu.anifantakis.lib.ksafe.internal.keyvault

import eu.anifantakis.lib.ksafe.internal.KSafeEngineMessage

/**
 * The wording that separates "the key store is temporarily unreachable" from "the key is genuinely
 * absent": [KSafeEngineMessage.VAULT_UNAVAILABLE], the same constant the core's classifier matches
 * on. It is a protocol, not prose — a vault that spells it differently silently destroys data,
 * because the orphan sweep then reads an outage as a definitively absent key.
 *
 * [failure] is what the vault tried, [reason] why it is believed unreachable — both stay per-vault,
 * the protocol phrase does not.
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
