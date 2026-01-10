package eu.anifantakis.lib.ksafe

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.runner.RunWith

/**
 * Android-specific instrumented test implementation for KSafe.
 * Runs on an actual Android device or emulator with real EncryptedSharedPreferences.
 */
@RunWith(AndroidJUnit4::class)
class AndroidKSafeTest : KSafeTest() {
    override fun createKSafe(fileName: String?): KSafe {
        val context = ApplicationProvider.getApplicationContext<Context>()
        return KSafe(context, fileName)
    }
}