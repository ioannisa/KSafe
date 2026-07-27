package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeAliasFormat
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeReservedKeys
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.requireValidStoreFileName
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Injectivity of the alias grammar, as a property rather than a list of remembered witnesses.
 *
 * Every OS key store KSafe writes into is ONE flat namespace shared by every store instance on
 * the device: the Android Keystore, the Apple Keychain, the JVM vault, the web key store. Two
 * distinct logical identities that spell the same alias share one physical key — rotating,
 * tightening or deleting either destroys the other's data. So the map
 *
 *     (userKey x namespace x generation x strict/master/marker) -> alias
 *
 * must be injective, modulo one documented exception (see [isLegalByDesign]).
 *
 * THE COUPLING THAT MAKES THIS A TEST OF THE GUARD, NOT JUST OF THE FORMAT: a generated user key
 * that `requireWritableUserKey` rejects is SKIPPED, because such an entry cannot exist. Weaken
 * the guard and the skipped keys re-enter the corpus, collide, and turn this test red. The alias
 * format and the reservation guard are therefore locked to each other by construction.
 *
 * The corpus is adversarial by design and generated from a deterministic seeded LCG, never a
 * platform RNG: a failure here must reproduce byte-for-byte on every target.
 */
class KSafeAliasInjectivityTest {

    // ---- identity model --------------------------------------------------------------------

    private enum class Kind { MASTER, MASTER_LOCKED, PER_ENTRY, STRICT }

    /** A marker record hung off a vault alias; `null` is the alias itself. */
    private enum class Marker { TOMBSTONE, SOFTWARE_FALLBACK }

    private data class Identity(
        val namespace: String?,
        /** `null` for the two master kinds, which have no user key. */
        val userKey: String?,
        val generation: Int,
        val kind: Kind,
        val marker: Marker?,
    )

    /** The two alias spellings; a store uses one, but every store on a platform shares its plane. */
    private enum class Plane { DOTTED, COLON }

    private fun join(plane: Plane, namespace: String?, key: String): String = when (plane) {
        Plane.DOTTED -> KSafeAliasFormat.dotted(namespace, key)
        Plane.COLON -> KSafeAliasFormat.colon(namespace, key)
    }

    /**
     * How a DEFAULT store must spell [key] for its base alias to land on the named store
     * [namespace]'s: the plane's delimiter, WITHOUT the store-identity prefix the dotted format
     * prepends to both sides anyway. This is the "dotted user key" of the documented collision.
     */
    private fun twinSpelling(plane: Plane, namespace: String, key: String): String = when (plane) {
        Plane.DOTTED -> "$namespace.$key"
        Plane.COLON -> "$namespace:$key"
    }

    /** The base alias a generation suffix hangs off — the identity's collision point at generation 1. */
    private fun baseAlias(plane: Plane, id: Identity): String = when (id.kind) {
        Kind.MASTER -> join(plane, id.namespace, KSafeReservedKeys.MASTER)
        Kind.MASTER_LOCKED -> join(plane, id.namespace, KSafeReservedKeys.MASTER_LOCKED)
        Kind.PER_ENTRY, Kind.STRICT -> join(plane, id.namespace, id.userKey!!)
    }

    /** Exactly how production spells this identity's physical key name. */
    private fun alias(plane: Plane, id: Identity): String {
        val base = baseAlias(plane, id)
        val core = when (id.kind) {
            Kind.MASTER, Kind.MASTER_LOCKED -> KSafeCore.aliasWithGeneration(base, id.generation)
            Kind.PER_ENTRY -> KSafeCore.perEntryAliasWithGeneration(
                base, id.generation, id.namespace, id.userKey!!,
            )
            Kind.STRICT -> KSafeCore.strictPerEntryAliasWithGeneration(
                base, id.generation, id.namespace, id.userKey!!,
            )
        }
        return when (id.marker) {
            null -> core
            Marker.TOMBSTONE -> "$core.${KSafeReservedKeys.VAULT_TOMBSTONE}"
            Marker.SOFTWARE_FALLBACK -> "$core.${KSafeReservedKeys.VAULT_SOFTWARE_FALLBACK}"
        }
    }

    /**
     * THE ALLOWLIST — one entry, deliberate and documented.
     *
     * At generation 1 the relaxed per-entry alias IS the bare base alias: the exact name every
     * pre-rotation release minted, frozen so existing keys need no migration. A default store's
     * joined key (`"vault.token"` / `"vault:token"`) therefore spells the same base as the named
     * store `"vault"`'s key `"token"`, and any marker hung off it inherits that. This is the
     * documented published-format collision called out in
     * `KSafeCore.perEntryAliasWithGeneration`; the fingerprint closes it for every rotated
     * generation and the strict variant never had it.
     *
     * Nothing else is legal. A second entry here would be a format change, not a test fix.
     */
    private fun isLegalByDesign(plane: Plane, a: Identity, b: Identity): Boolean =
        a.kind == Kind.PER_ENTRY && b.kind == Kind.PER_ENTRY &&
            a.generation == 1 && b.generation == 1 &&
            a.marker == b.marker &&
            baseAlias(plane, a) == baseAlias(plane, b)

    // ---- deterministic corpus --------------------------------------------------------------

    /** 64-bit LCG (Knuth's MMIX constants). Seeded and platform-independent — a failure reproduces. */
    private class Lcg(private var state: Long) {
        fun nextInt(bound: Int): Int {
            state = state * 6364136223846793005L + 1442695040888963407L
            return ((state ushr 33).toInt() and 0x7fffffff) % bound
        }
        fun <T> pick(from: List<T>): T = from[nextInt(from.size)]
    }

    private val namespaces = listOf(null, "v", "va", "vault", "vault2", "a_b")
    private val generations = listOf(1, 2, 3, 7, KeySafeMetadataManager.MAX_KEY_GENERATION)
    private val markers = listOf(null, Marker.TOMBSTONE, Marker.SOFTWARE_FALLBACK)

    /** Fragments that make an accidental alias spelling as likely as the generator can manage. */
    private fun fragments(): List<String> {
        // Real fingerprints of identities that ARE in the corpus: a user key carrying the exact
        // hex its neighbour's rotated alias ends in was a live collision once.
        val realFingerprints = buildList {
            for (ns in namespaces) for (k in listOf("foo", "token", "a.b", "")) {
                add(".h${KSafeCore.aliasFingerprint(ns, k)}")
            }
        }
        return listOf(
            "", "a", "b", "foo", "token", "vault", "v", "va", "vault2", "a_b",
            ".", ":", "..", "::", ".:", ":.", "_", "-",
            // `.gN` tails: the suffix the grammar itself appends.
            ".g1", ".g2", ".g3", ".g0", ".g10000", ".g99999", ".g", "g2",
            // Real sentinels (the guard must keep every one of these out) and near-misses.
            KSafeReservedKeys.MASTER, KSafeReservedKeys.MASTER_LOCKED,
            KSafeReservedKeys.STRICT_VARIANT, KSafeReservedKeys.ROTATED_VARIANT,
            KSafeReservedKeys.VAULT_TOMBSTONE, KSafeReservedKeys.VAULT_SOFTWARE_FALLBACK,
            "__ksafe_", "__ksafe_gen_", "_ksafe_gen__", "__KSAFE_GEN__", "__ksafe_genx__",
            "__ksafe_strict_", "ksafe_master__",
            // Fingerprint-shaped tails, real hex and not.
            ".h0123456789abcdef", ".hffffffffffffffff", ".hZZZZZZZZZZZZZZZZ",
            // Line terminators (a default regex `.` skips them) and invisible spacing.
            "\n", "\r", "\r\n", "\u2028", "\u2029", "\u0085", "\u00a0", "\u200b", "\u202e",
            // Unicode, including a non-ASCII digit right where `\d` would be parsed.
            "\u00e9", "\u65e5\u672c", "\ud83d\udd10", "\u0301", "\u0662", "\uff0e", "\uff1a",
            // The store-identity prefix itself.
            "eu.anifantakis.ksafe", "eu.anifantakis.ksafe.vault",
        ) + realFingerprints
    }

    /** User keys a store could actually hold: the guard rejects the rest, so they cannot collide. */
    private fun writableKeys(plane: Plane, lcg: Lcg): List<String> {
        val frags = fragments()
        val keys = LinkedHashSet<String>()
        keys += ""
        keys += "z".repeat(4000) // very long
        repeat(12_000) {
            val sb = StringBuilder()
            repeat(1 + lcg.nextInt(4)) { sb.append(lcg.pick(frags)) }
            keys += sb.toString()
        }
        // Deliberate cross-namespace twins: the same logical entry reached as a named store's
        // bare key and as the default store's joined key. Random generation would hit these only
        // by luck and they are the whole point.
        for (ns in namespaces.filterNotNull()) {
            for (k in twinBaseKeys) keys += twinSpelling(plane, ns, k)
        }
        keys += aliasLookalikeKeys()
        return keys.filter { runCatching { KeySafeMetadataManager.requireWritableUserKey(it) }.isSuccess }
    }

    private val twinBaseKeys =
        listOf("token", "foo", "", "a.b", ".g2", "__ksafe_master__", "x.__ksafe_strict__")

    /**
     * User keys that SPELL another identity's alias, planted exhaustively rather than left to the
     * generator: hitting a specific three-fragment composition by chance is a fraction of a
     * percent, and these are the shapes that actually went wrong. Every historical rotated-alias
     * format is here — the bare `.gN` suffix, the fingerprint-only suffix, and the current
     * sentinel-bearing one — so removing any of the disambiguators from the format collides.
     * The reserved shapes are dropped by the guard filter; that is the guard doing its job.
     */
    private fun aliasLookalikeKeys(): List<String> = buildList {
        for (ns in namespaces) {
            for (key in listOf("foo", "token", "a.b", "")) {
                val fingerprint = KSafeCore.aliasFingerprint(ns, key)
                for (generation in listOf(2, 3, 7)) {
                    add("$key.g$generation")
                    add("$key.g$generation.h$fingerprint")
                    add("$key.g$generation.${KSafeReservedKeys.ROTATED_VARIANT}.h$fingerprint")
                }
                add("$key.h$fingerprint")
                add("$key.${KSafeReservedKeys.STRICT_VARIANT}.h$fingerprint")
                add("$key.${KSafeReservedKeys.VAULT_TOMBSTONE}")
                add("$key.${KSafeReservedKeys.VAULT_SOFTWARE_FALLBACK}")
            }
        }
    }

    /** ~[target] distinct identities: every master slot, the twins exhaustively, the rest sampled. */
    private fun corpus(plane: Plane, target: Int): List<Identity> {
        val lcg = Lcg(0x5AFE00002300_0001L)
        val keys = writableKeys(plane, lcg)
        val identities = LinkedHashSet<Identity>()

        for (ns in namespaces) {
            requireValidStoreFileName(ns) // the corpus must only contain constructible stores
            for (generation in generations) {
                for (marker in markers) {
                    identities += Identity(ns, null, generation, Kind.MASTER, marker)
                    identities += Identity(ns, null, generation, Kind.MASTER_LOCKED, marker)
                }
            }
        }
        // The twins and the alias lookalikes, exhaustively rather than by sampling.
        val twinKeys = (twinBaseKeys + aliasLookalikeKeys() + namespaces.filterNotNull().flatMap { ns ->
            twinBaseKeys.map { twinSpelling(plane, ns, it) }
        }).filter { runCatching { KeySafeMetadataManager.requireWritableUserKey(it) }.isSuccess }
        for (ns in namespaces) {
            for (key in twinKeys) {
                for (generation in generations) {
                    for (marker in markers) {
                        identities += Identity(ns, key, generation, Kind.PER_ENTRY, marker)
                        identities += Identity(ns, key, generation, Kind.STRICT, marker)
                    }
                }
            }
        }
        // Sample the adversarial corpus up to the target.
        var attempts = 0
        while (identities.size < target && attempts < target * 8) {
            attempts++
            identities += Identity(
                namespace = lcg.pick(namespaces),
                userKey = lcg.pick(keys),
                generation = lcg.pick(generations),
                kind = if (lcg.nextInt(2) == 0) Kind.PER_ENTRY else Kind.STRICT,
                marker = lcg.pick(markers),
            )
        }
        return identities.toList()
    }

    // ---- the property ----------------------------------------------------------------------

    private fun assertInjective(plane: Plane) {
        val target = 20_000
        val identities = corpus(plane, target)
        assertTrue(
            identities.size >= target,
            "the corpus must reach the target size to be worth running (was ${identities.size})",
        )
        val byAlias = HashMap<String, Identity>(identities.size * 2)
        var legalCollisions = 0
        for (id in identities) {
            val alias = alias(plane, id)
            val previous = byAlias.put(alias, id)
            if (previous == null || previous == id) continue
            if (isLegalByDesign(plane, previous, id)) {
                legalCollisions++
                continue
            }
            fail(
                "ALIAS COLLISION on the $plane plane — two distinct identities share one physical " +
                    "key, so mutating either destroys the other:\n" +
                    "  alias = ${alias.debug()}\n" +
                    "  A     = ${previous.debug()}\n" +
                    "  B     = ${id.debug()}\n" +
                    "The 3.0.0 alias format is about to be frozen by the tag: this is a format " +
                    "decision for the owner, NOT something to patch in the test."
            )
        }
        assertTrue(
            legalCollisions > 0,
            "precondition: the corpus must actually exercise the documented generation-1 " +
                "base-alias collision, otherwise the allowlist is untested",
        )
    }

    @Test
    fun aliasesAreInjective_onTheDottedPlane() = assertInjective(Plane.DOTTED)

    @Test
    fun aliasesAreInjective_onTheColonPlane() = assertInjective(Plane.COLON)

    @Test
    fun theDocumentedGeneration1Collision_closesAtEveryRotatedGeneration() {
        // States the allowlist's boundary directly: the twins it covers at generation 1 must
        // diverge the moment either is rotated, and must never have collided under the strict
        // variant. This is what keeps the allowlist from quietly widening.
        for (plane in Plane.entries) {
            val defaultStoreKey = twinSpelling(plane, "vault", "token")
            val a = Identity("vault", "token", 1, Kind.PER_ENTRY, null)
            val b = Identity(null, defaultStoreKey, 1, Kind.PER_ENTRY, null)
            assertTrue(
                alias(plane, a) == alias(plane, b),
                "precondition: the documented generation-1 twins must actually collide on $plane",
            )
            for (generation in listOf(2, 3, KeySafeMetadataManager.MAX_KEY_GENERATION)) {
                assertTrue(
                    alias(plane, a.copy(generation = generation)) !=
                        alias(plane, b.copy(generation = generation)),
                    "rotated generation $generation must separate the twins on $plane",
                )
            }
            assertTrue(
                alias(plane, a.copy(kind = Kind.STRICT)) != alias(plane, b.copy(kind = Kind.STRICT)),
                "the strict variant must separate the twins on $plane even at generation 1",
            )
        }
    }

    // ---- readable failures -----------------------------------------------------------------

    private fun Identity.debug(): String =
        "Identity(ns=${namespace?.let { "\"$it\"" }}, key=${userKey?.debug()}, " +
            "g=$generation, kind=$kind, marker=$marker)"

    private fun String.debug(): String {
        val shown = if (length > 96) substring(0, 96) + "…(len=$length)" else this
        return "\"" + shown.map { c ->
            if (c.code in 32..126) "$c" else "\\u${c.code.toString(16).padStart(4, '0')}"
        }.joinToString("") + "\""
    }
}
