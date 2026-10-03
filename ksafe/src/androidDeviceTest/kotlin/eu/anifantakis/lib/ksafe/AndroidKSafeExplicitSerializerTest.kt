package eu.anifantakis.lib.ksafe

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.runner.RunWith

/** Android instrumented binding for the shared explicit-serializer suite. */
@RunWith(AndroidJUnit4::class)
class AndroidKSafeExplicitSerializerTest : KSafeExplicitSerializerTest() {
    override fun newKSafe(fileName: String?): KSafe {
        val context = ApplicationProvider.getApplicationContext<Context>()
        // Its own store: the default one is shared with the other instrumented suites.
        return KSafe(context, fileName ?: "explicit_${System.nanoTime()}")
    }
}
