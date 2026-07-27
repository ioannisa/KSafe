package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager.stableStoreIdentity
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

/**
 * Locks in: the v3 AAD store identity is HOME-RELATIVE, so an OS-relocated home (the iOS
 * app-container UUID changes on every App Store update/restore; a JVM user home can move)
 * yields the SAME identity — an absolute path would make every rotated entry fail its AAD
 * after an ordinary app update, and the startup orphan sweep would then delete it.
 */
class StableStoreIdentityTest {

    @Test
    fun containerRelocation_keepsTheIdentityStable() {
        // The exact iOS App Store update scenario: same logical store, new container UUID.
        val before = stableStoreIdentity(
            "/var/mobile/Containers/Data/Application/AAAA-1111/Library/Application Support/ks/data.preferences_pb",
            "/var/mobile/Containers/Data/Application/AAAA-1111",
        )
        val after = stableStoreIdentity(
            "/var/mobile/Containers/Data/Application/BBBB-2222/Library/Application Support/ks/data.preferences_pb",
            "/var/mobile/Containers/Data/Application/BBBB-2222",
        )
        assertEquals(before, after, "a container relocation must not change the AAD identity")
        assertEquals("~/Library/Application Support/ks/data.preferences_pb", before)
    }

    @Test
    fun distinctLogicalStores_keepDistinctIdentities() {
        val home = "/var/mobile/Containers/Data/Application/AAAA-1111"
        assertNotEquals(
            stableStoreIdentity("$home/Library/ks/a.preferences_pb", home),
            stableStoreIdentity("$home/Library/ks/b.preferences_pb", home),
            "different fileName must keep the anti-transplant property",
        )
        assertNotEquals(
            stableStoreIdentity("$home/Library/dir1/a.preferences_pb", home),
            stableStoreIdentity("$home/Library/dir2/a.preferences_pb", home),
            "different directory must keep the anti-transplant property",
        )
    }

    @Test
    fun posixBackslashPaths_stayDistinct() {
        // Backslash is a legal POSIX filename char; collapsing it would map two distinct files
        // to one identity and let a rotated ciphertext transplant between key-sharing stores.
        assertNotEquals(
            stableStoreIdentity("""/data/a\b/store.json""", "/home/user"),
            stableStoreIdentity("/data/a/b/store.json", "/home/user"),
            "a POSIX backslash must not be normalized to a slash",
        )
    }

    @Test
    fun aPathBeginningWithTheHomeSigil_cannotCollideWithAHomeRelativeIdentity() {
        // A caller directory literally beginning with "~/" (an unexpanded tilde passed verbatim)
        // must not produce the same identity as a genuinely home-relative store.
        val homeRelative = stableStoreIdentity("/home/user/ks/store.json", "/home/user")
        val literalTilde = stableStoreIdentity("~/ks/store.json", "/some/other/home")
        assertEquals("~/ks/store.json", homeRelative)
        assertNotEquals(homeRelative, literalTilde, "a literal ~/ path must be escaped, not passed through")
    }

    @Test
    fun pathsOutsideTheHome_andMissingHome_stayAsPassed() {
        assertEquals(
            "/opt/data/store.json",
            stableStoreIdentity("/opt/data/store.json", "/home/user"),
            "a path outside the home must stay absolute",
        )
        assertEquals(
            "/home/user/store.json",
            stableStoreIdentity("/home/user/store.json", null),
            "a null home leaves the path unchanged",
        )
        assertEquals(
            "/home/user/store.json",
            stableStoreIdentity("/home/user/store.json", ""),
            "an empty home leaves the path unchanged",
        )
    }

    @Test
    fun trailingSlashAndWindowsSeparators_areNormalized()
    {
        assertEquals(
            "~/data/store.json",
            stableStoreIdentity("/home/user/data/store.json", "/home/user/"),
            "a trailing-slash home must strip identically",
        )
        assertEquals(
            "~/AppData/ks/store.json",
            stableStoreIdentity("""C:\Users\x\AppData\ks\store.json""", """C:\Users\x"""),
            "Windows separators must normalize before the prefix match",
        )
        // A sibling user's home must NOT be treated as a prefix ("/home/us" vs "/home/user").
        assertEquals(
            "/home/user2/store.json",
            stableStoreIdentity("/home/user2/store.json", "/home/user"),
            "a home that is a string-prefix but not a path-prefix must not match",
        )
    }
}
