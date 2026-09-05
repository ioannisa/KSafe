package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.resolveStoreIdentity
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * Locks in which path spelling the v3 AAD identity is derived from. Windows' `getCanonicalPath()`
 * normalizes case and 8.3 names but walks through a symlink or junction, so the link-resolved real
 * path is the primary identity and the spelling earlier builds shipped stays the fallback — a
 * store already written under a junction must keep decrypting.
 */
class JvmStoreIdentityResolutionTest {

    private val root = File(System.getProperty("java.io.tmpdir"), "ksafe_ident_${System.nanoTime()}").apply { mkdirs() }

    @AfterTest fun tearDown() { root.deleteRecursively() }

    @Test
    fun windowsJunction_primaryIsTheRealPath_fallbackIsTheShippedCanonicalOne() {
        val identity = resolveStoreIdentity(
            canonicalPath = """C:\Users\runneradmin\link\ks\eu_anifantakis_ksafe_datastore_v""",
            canonicalHome = """C:\Users\runneradmin""",
            rawPath = """C:\Users\RUNNER~1\link\ks\eu_anifantakis_ksafe_datastore_v""",
            rawHome = """C:\Users\RUNNER~1""",
            realPath = """C:\Users\runneradmin\real\ks\eu_anifantakis_ksafe_datastore_v""",
            realHome = """C:\Users\runneradmin""",
        )
        assertEquals("~/real/ks/eu_anifantakis_ksafe_datastore_v", identity.canonical)
        assertEquals(
            "~/link/ks/eu_anifantakis_ksafe_datastore_v", identity.fallback,
            "a store written by a build that stopped at the junction must stay decryptable",
        )
    }

    @Test
    fun bothSpellingsOfOneJunctionedStore_shareTheIdentity() {
        val real = """C:\Users\runneradmin\real\ks\eu_anifantakis_ksafe_datastore_v"""
        val viaLink = resolveStoreIdentity(
            canonicalPath = """C:\Users\runneradmin\link\ks\eu_anifantakis_ksafe_datastore_v""",
            canonicalHome = """C:\Users\runneradmin""",
            rawPath = """C:\Users\runneradmin\link\ks\eu_anifantakis_ksafe_datastore_v""",
            rawHome = """C:\Users\runneradmin""",
            realPath = real,
            realHome = """C:\Users\runneradmin""",
        )
        val viaReal = resolveStoreIdentity(
            canonicalPath = real,
            canonicalHome = """C:\Users\runneradmin""",
            rawPath = real,
            rawHome = """C:\Users\runneradmin""",
            realPath = real,
            realHome = """C:\Users\runneradmin""",
        )
        assertEquals(viaReal.canonical, viaLink.canonical, "one physical store must carry one identity")
    }

    @Test
    fun whereLinksAlreadyResolve_theRawSpellingStaysTheFallback() {
        // POSIX: canonicalPath IS the real path, so the raw (unresolved) spelling keeps the slot.
        val identity = resolveStoreIdentity(
            canonicalPath = "/private/var/t/ks/eu_anifantakis_ksafe_datastore_v",
            canonicalHome = "/Users/u",
            rawPath = "/var/t/ks/eu_anifantakis_ksafe_datastore_v",
            rawHome = "/Users/u",
            realPath = "/private/var/t/ks/eu_anifantakis_ksafe_datastore_v",
            realHome = "/Users/u",
        )
        assertEquals("/private/var/t/ks/eu_anifantakis_ksafe_datastore_v", identity.canonical)
        assertEquals("/var/t/ks/eu_anifantakis_ksafe_datastore_v", identity.fallback)
    }

    @Test
    fun noRealPath_keepsThePreviousCanonicalOverRawShape() {
        val identity = resolveStoreIdentity(
            canonicalPath = "/private/var/t/ks/eu_anifantakis_ksafe_datastore_v",
            canonicalHome = "/Users/u",
            rawPath = "/var/t/ks/eu_anifantakis_ksafe_datastore_v",
            rawHome = "/Users/u",
        )
        assertEquals("/private/var/t/ks/eu_anifantakis_ksafe_datastore_v", identity.canonical)
        assertEquals("/var/t/ks/eu_anifantakis_ksafe_datastore_v", identity.fallback)
    }

    @Test
    fun everySpellingAgrees_leavesNoFallback() {
        val identity = resolveStoreIdentity(
            canonicalPath = "/opt/ks/eu_anifantakis_ksafe_datastore_v",
            canonicalHome = "/Users/u",
            rawPath = "/opt/ks/eu_anifantakis_ksafe_datastore_v",
            rawHome = "/Users/u",
            realPath = "/opt/ks/eu_anifantakis_ksafe_datastore_v",
            realHome = "/Users/u",
        )
        assertEquals("", identity.fallback)
    }

    @Test
    fun realStorePath_resolvesALinkedDirectory_andANotYetCreatedStoreName() {
        val realDir = File(root, "real").apply { mkdirs() }
        val link = File(root, "link")
        Files.createSymbolicLink(link.toPath(), realDir.toPath())

        assertEquals(realDir.canonicalPath, realStorePath(link))
        // The store's base name is a prefix, never a file: it resolves through its parent.
        assertEquals(
            File(realDir.canonicalPath, "eu_anifantakis_ksafe_datastore_v").path,
            realStorePath(File(link, "eu_anifantakis_ksafe_datastore_v")),
        )
    }

    @Test
    fun realStorePath_isNullWhenNothingOnThePathExists() {
        assertNull(realStorePath(File(File(root, "absent"), "eu_anifantakis_ksafe_datastore_v")))
    }
}
