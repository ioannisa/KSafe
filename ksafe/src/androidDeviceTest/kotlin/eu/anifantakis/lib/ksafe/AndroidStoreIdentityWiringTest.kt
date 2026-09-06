package eu.anifantakis.lib.ksafe

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import kotlin.test.assertTrue

/**
 * Locks in that the Android factory WIRES the identity home-relative, not merely that the helper can:
 * `applicationInfo.dataDir` is a symlink, so canonicalizing the store path while leaving that prefix
 * raw leaves the identity absolute — which shipped once with every host test green. An absolute
 * identity breaks the day the OS moves the app's data, and the sweep then reaps every rotated entry.
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
