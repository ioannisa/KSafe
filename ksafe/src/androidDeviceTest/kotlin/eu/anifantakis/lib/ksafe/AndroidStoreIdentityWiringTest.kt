package eu.anifantakis.lib.ksafe

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import kotlin.test.assertTrue

/**
 * Locks in that the Android factory WIRES the store identity home-relative, not merely that the
 * helper computing it can.
 *
 * Android is where this breaks and nowhere else can see it: `applicationInfo.dataDir` is
 * `/data/user/0/<pkg>`, a symlink to `/data/data/<pkg>`. Canonicalizing the store path while
 * leaving that prefix raw means the two can never match, so the identity silently stays absolute —
 * which shipped once, with every host test green, because feeding the helper hand-written
 * arguments cannot see which arguments the factory actually passes.
 *
 * An absolute identity survives until the OS moves the app's data (adoptable storage, restore),
 * and then every rotated entry fails authentication and the startup sweep treats it as an orphan.
 */
@RunWith(AndroidJUnit4::class)
class AndroidStoreIdentityWiringTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Test
    fun theIdentityIsHomeRelative_evenThoughDataDirIsASymlink() {
        val rawDataDir = context.applicationInfo.dataDir
        val canonicalDataDir = File(rawDataDir).canonicalPath

        val ksafe = KSafe(context = context, fileName = "identity_wiring_${System.nanoTime()}")
        try {
            val identity = ksafe.core.storeIdentity
            assertTrue(
                identity.startsWith("~/"),
                "identity must be home-relative; got '$identity' " +
                    "(raw dataDir=$rawDataDir, canonical=$canonicalDataDir)",
            )
            assertTrue(
                !identity.contains(canonicalDataDir) && !identity.contains(rawDataDir),
                "a home-relative identity must not still carry either spelling of the data dir: $identity",
            )
        } finally {
            ksafe.close()
        }
    }

    @Test
    fun theTwoDataDirSpellingsDiffer_soThisTestCanFail() {
        // Guards the test itself: if the platform ever stopped symlinking, the assertion above
        // would pass for the wrong reason and quietly stop covering anything.
        val raw = context.applicationInfo.dataDir
        assertTrue(
            raw != File(raw).canonicalPath,
            "expected /data/user/0/<pkg> to be a symlink; without that this test proves nothing",
        )
    }
}
