package eu.anifantakis.lib.ksafe

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.runner.RunWith

/** Android instrumented binding for the shared mode-views suite. */
@RunWith(AndroidJUnit4::class)
class AndroidKSafeModeViewsTest : KSafeModeViewsTest() {
    override fun newKSafe(fileName: String?): KSafe {
        val context = ApplicationProvider.getApplicationContext<Context>()
        return KSafe(context, fileName)
    }
}
