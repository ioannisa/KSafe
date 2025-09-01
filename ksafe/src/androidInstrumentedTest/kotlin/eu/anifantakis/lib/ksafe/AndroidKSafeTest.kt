package eu.anifantakis.lib.ksafe

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidKSafeTest : KSafeTest() {
    override fun createKSafe(fileName: String?): KSafe {
        val context = ApplicationProvider.getApplicationContext<Context>()
        return KSafe(context, fileName)
    }
}