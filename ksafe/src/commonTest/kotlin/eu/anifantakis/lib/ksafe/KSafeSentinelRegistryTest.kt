package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeAliasFormat
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeReservedKeys
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Locks in: the reserved-sentinel registry is complete in both directions — every entry is rejected
 * as a user key behind both alias delimiters (`.` for Android/Apple, `:` for JVM/web), and every
 * sentinel the alias producers actually emit is an entry. The colon was missing once, and the user
 * key `"vault:__ksafe_master__"` could write and delete the `"vault"` store's master key.
 */
class KSafeSentinelRegistryTest {

    /**
     * Referenced, never re-typed. Kotlin has no common-source reflection over an object's members,
     * so this list is the one hand-maintained copy — which is why
     * [everySentinelTheAliasProducersEmit_isRegisteredAndReserved] does not use it.
     */
    private val registry = listOf(
        KSafeReservedKeys.MASTER,
        KSafeReservedKeys.MASTER_LOCKED,
        KSafeReservedKeys.STRICT_VARIANT,
        KSafeReservedKeys.ROTATED_VARIANT,
        KSafeReservedKeys.VAULT_TOMBSTONE,
        KSafeReservedKeys.VAULT_SOFTWARE_FALLBACK,
    )

    /** `.` joins Android/Apple aliases, `:` joins JVM/web ones; both reach the same guard. */
    private val delimiters = listOf(".", ":")

    private fun assertRejected(key: String, why: String) {
        val outcome = runCatching { KeySafeMetadataManager.requireWritableUserKey(key) }
        if (outcome.isSuccess) fail("$why — requireWritableUserKey accepted ${key.debug()}")
    }

    // ---- registry -> guard ---------------------------------------------------------------

    @Test
    fun everyRegisteredSentinel_isReservedBehindBothPlatformAliasDelimiters() {
        for (sentinel in registry) {
            // The bare sentinel is caught by the `__ksafe_` namespace rule, not the suffix rule.
            assertRejected(sentinel, "a bare registry sentinel must never be a writable user key")
            for (delimiter in delimiters) {
                for (prefix in listOf("x", "vault", "a.b", "a:b", "", "a\nb")) {
                    assertRejected(
                        "$prefix$delimiter$sentinel",
                        "sentinel '$sentinel' behind the '$delimiter' delimiter must be reserved",
                    )
                }
            }
        }
    }

    @Test
    fun everyRegisteredSentinel_isReservedInEveryShapeItsProducerCanDecorateItWith() {
        // The guard matches the sentinel plus the decoration its producer appends: a generation
        // suffix on a master alias, a fingerprint on a per-entry variant. Undecorated forms are
        // covered above; the JVM markers take no decoration.
        val fingerprint = KSafeCore.aliasFingerprint("vault", "token")
        val decorated = mapOf(
            KSafeReservedKeys.MASTER to listOf(".g2", ".g10000"),
            KSafeReservedKeys.MASTER_LOCKED to listOf(".g2", ".g10000"),
            KSafeReservedKeys.STRICT_VARIANT to listOf(".h$fingerprint"),
            KSafeReservedKeys.ROTATED_VARIANT to listOf(".h$fingerprint"),
        )
        for ((sentinel, decorations) in decorated) {
            for (decoration in decorations) {
                for (delimiter in delimiters) {
                    assertRejected(
                        "x$delimiter$sentinel$decoration",
                        "decorated sentinel '$sentinel$decoration' must be reserved behind '$delimiter'",
                    )
                }
            }
        }
    }

    // ---- producers -> registry -----------------------------------------------------------

    /** `__`-fenced lowercase segment: the shape every KSafe sentinel is spelled in. */
    private val sentinelShape = Regex("""__[a-z0-9_]*?__""")

    /**
     * Every alias KSafe writes, produced by the real producers. User keys and store names here
     * are deliberately sentinel-free, so any sentinel found in the output came from a producer.
     */
    private fun producedAliases(): List<String> {
        val aliases = mutableListOf<String>()
        val joins = listOf<(String?, String) -> String>(
            { f, k -> KSafeAliasFormat.dotted(f, k) },
            { f, k -> KSafeAliasFormat.colon(f, k) },
        )
        for (fileName in listOf(null, "vault")) {
            for (join in joins) {
                // Master aliases: the base is assembled by the platform factories, each reading the
                // sentinel from the registry — commonTest cannot reach a platform source set.
                for (master in listOf(KSafeReservedKeys.MASTER, KSafeReservedKeys.MASTER_LOCKED)) {
                    val base = join(fileName, master)
                    for (generation in listOf(1, 2, 10_000)) {
                        aliases += KSafeCore.aliasWithGeneration(base, generation)
                    }
                }
                for (userKey in listOf("token", "a.b", "a:b")) {
                    val base = join(fileName, userKey)
                    for (generation in listOf(1, 2, 10_000)) {
                        aliases += KSafeCore.perEntryAliasWithGeneration(base, generation, fileName, userKey)
                        aliases += KSafeCore.strictPerEntryAliasWithGeneration(base, generation, fileName, userKey)
                    }
                }
            }
        }
        // The JVM vault markers wrap an arbitrary vault alias; their producers are private to
        // jvmMain and spell it "<alias>.<registry entry>", reproduced here to cover that plane too.
        return aliases + aliases.flatMap {
            listOf(
                "$it.${KSafeReservedKeys.VAULT_TOMBSTONE}",
                "$it.${KSafeReservedKeys.VAULT_SOFTWARE_FALLBACK}",
            )
        }
    }

    @Test
    fun everySentinelTheAliasProducersEmit_isRegisteredAndReserved() {
        val aliases = producedAliases()
        var sentinelsSeen = 0
        for (alias in aliases) {
            for (match in sentinelShape.findAll(alias)) {
                sentinelsSeen++
                assertTrue(
                    match.value in registry,
                    "alias ${alias.debug()} contains sentinel '${match.value}', which is not in " +
                        "KSafeReservedKeys — an unregistered sentinel is not covered by " +
                        "requireWritableUserKey's pattern, so a user key can alias it",
                )
                // The reservation must cover the whole tail, not just the sentinel: a user key
                // spelling that tail behind either delimiter is a byte-identical alias to this one.
                val tail = alias.substring(match.range.first)
                for (delimiter in delimiters) {
                    assertRejected(
                        "x$delimiter$tail",
                        "the produced alias tail '$tail' (from $alias) must be reserved behind '$delimiter'",
                    )
                }
            }
        }
        assertTrue(
            sentinelsSeen > 0,
            "precondition: the producers must emit sentinels, otherwise this test asserts nothing",
        )
    }

    /** Renders line terminators and other invisibles so a failure message is readable. */
    private fun String.debug(): String =
        "\"" + map { c -> if (c.code in 32..126) "$c" else "\\u${c.code.toString(16).padStart(4, '0')}" }
            .joinToString("") + "\""
}
