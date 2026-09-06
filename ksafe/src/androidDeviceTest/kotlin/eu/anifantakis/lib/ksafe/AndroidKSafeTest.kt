package eu.anifantakis.lib.ksafe

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.runner.RunWith

/** Runs the shared KSafe suite instrumented, on a real device or emulator. */
@RunWith(AndroidJUnit4::class)
class AndroidKSafeTest : KSafeTest() {
    override fun newKSafe(fileName: String?): KSafe {
        val context = ApplicationProvider.getApplicationContext<Context>()
        return KSafe(context, fileName)
    }
}