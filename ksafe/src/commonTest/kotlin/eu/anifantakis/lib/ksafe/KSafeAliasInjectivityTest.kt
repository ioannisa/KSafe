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
 * Locks in: the map (userKey x namespace x generation x strict/master/marker) -> alias is injective,
 * modulo the one exception in [isLegalByDesign]. Each OS key store is one flat namespace, so two
 * identities spelling the same alias share a physical key and mutating either destroys the other.
 * Keys `requireWritableUserKey` rejects are skipped, which locks the alias format to the guard.
 */
class KSafeAliasInjectivityTest {

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
     * How a default store must spell [key] for its base alias to land on the named store
     * [namespace]'s: the plane's delimiter, without the store-identity prefix the dotted format
     * prepends to both sides anyway.
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
     * The one legal collision, and a second entry here would be a format change rather than a test
     * fix: at generation 1 the relaxed per-entry alias is the bare base alias — the name every
     * pre-rotation release minted — so a default store's joined key `"vault.token"` spells the same
     * base as store `"vault"`'s key `"token"`. Rotation's fingerprint closes it; strict never had it.
     */
    private fun isLegalByDesign(plane: Plane, a: Identity, b: Identity): Boolean =
        a.kind == Kind.PER_ENTRY && b.kind == Kind.PER_ENTRY &&
            a.generation == 1 && b.generation == 1 &&
            a.marker == b.marker &&
            baseAlias(plane, a) == baseAlias(plane, b)

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
        // Real fingerprints of identities in the corpus: a user key carrying the exact hex its
        // neighbour's rotated alias ends in was a live collision once.
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
        keys += "z".repeat(4000)
        repeat(12_000) {
            val sb = StringBuilder()
            repeat(1 + lcg.nextInt(4)) { sb.append(lcg.pick(frags)) }
            keys += sb.toString()
        }
        // Cross-namespace twins: one logical entry reached as a named store's bare key and as the
        // default store's joined key. The generator would hit these only by luck.
        for (ns in namespaces.filterNotNull()) {
            for (k in twinBaseKeys) keys += twinSpelling(plane, ns, k)
        }
        keys += aliasLookalikeKeys()
        return keys.filter { runCatching { KeySafeMetadataManager.requireWritableUserKey(it) }.isSuccess }
    }

    private val twinBaseKeys =
        listOf("token", "foo", "", "a.b", ".g2", "__ksafe_master__", "x.__ksafe_strict__")

    /**
     * User keys that spell another identity's alias, planted rather than left to the generator,
     * which would hit a specific three-fragment composition only by luck. Every historical
     * rotated-alias format is here — bare `.gN`, fingerprint-only, and the current sentinel-bearing
     * one — so dropping any disambiguator collides. Reserved shapes fall out to the guard filter.
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
        // The allowlist's boundary: its generation-1 twins must diverge the moment either is
        // rotated, and must never have collided under strict. This keeps the allowlist from widening.
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
