package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertNull

/**
 * FEEDBACK_4 FB3-H2: the post-commit repair re-asserts an encrypted write's
 * `memoryCache` / `protectionMap` / `encMetaMap` via three separate
 * `putIfAbsent`s (to survive a `clearAll` that wiped the optimistic state). Those
 * inserts race a caller-thread `delete()`, which claims `writeOwners` and wipes
 * all three maps synchronously. In the losing interleaving the value `putIfAbsent`
 * runs first as a no-op (our ciphertext still cached), the delete then wipes
 * everything, and the `protectionMap`/`encMetaMap` `putIfAbsent`s RESURRECT orphan
 * metadata for the now-deleted key. Because the coupled cleanup keyed off the
 * (now-absent) value's `removeIf`, it skipped the orphans — so `getKeyInfo`
 * returned non-null for a deleted key and `getOrCreateSecret` threw "refusing to
 * overwrite" forever (breaking delete-then-recreate / logout-relogin rotation).
 *
 * The interleaving is injected deterministically via the core's test-only
 * `postCommitRepairHook`, which fires at the exact point between the value insert
 * and the metadata inserts.
 */
class JvmPostCommitRepairDeleteRaceTest {

    private class IdentityEngine : KSafeEncryption {
        override fun encrypt(identifier: String, data: ByteArray, hardwareIsolated: Boolean, requireUnlockedDevice: Boolean?): ByteArray = data
        override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray = data
        override fun deleteKey(identifier: String) {}
    }

    @Test
    fun concurrentDeleteDuringRepair_doesNotResurrectMetadata_forDeletedEncryptedKey() {
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.LAZY_PLAIN_TEXT, // encrypted op → the Encrypted repair branch
            lazyLoad = true,                                  // no collector → no updateCache re-sync to mask the bug
            testEngine = IdentityEngine(),
        )

        // At the precise interleaving — right after the value putIfAbsent (a no-op,
        // our ciphertext still cached) — a delete claims ownership and wipes all
        // three maps, so the following protection/encMeta putIfAbsents resurrect
        // orphan metadata. Fire exactly once for "k".
        var fired = false
        ksafe.core.postCommitRepairHook = { userKey ->
            if (userKey == "k" && !fired) {
                fired = true
                ksafe.core.deleteDirect("k") // synchronous wipe + writeOwners claim
            }
        }

        runBlocking { ksafe.put("k", "v", KSafeWriteMode.Encrypted()) }

        // The key was deleted mid-repair. Its metadata must NOT be resurrected:
        // getKeyInfo must report it absent (before the fix, protectionMap/encMetaMap
        // stayed populated, so getKeyInfo returned non-null → getOrCreateSecret
        // permanently refused to recreate it).
        assertNull(
            ksafe.getKeyInfo("k"),
            "a delete racing the post-commit repair must not leave orphan protection/encMeta " +
                "for the deleted key (FB3-H2)",
        )

        ksafe.close()
    }
}
