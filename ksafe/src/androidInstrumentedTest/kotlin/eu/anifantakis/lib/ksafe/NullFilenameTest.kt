package eu.anifantakis.lib.ksafe

import android.content.Context
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.test.runTest
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.test.assertEquals

@RunWith(AndroidJUnit4::class)
class NullFilenameTest {
    
    @Test
    fun testWithNullFilename() = runTest {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val ksafe = KSafe(context, null)  // Explicitly passing null
        
        val key = "test_key"
        val value = "test_value"
        
        Log.d("NullFilenameTest", "Putting value with null filename")
        ksafe.put(key, value, encrypted = false)
        
        val retrieved = ksafe.get(key, "default", encrypted = false)
        Log.d("NullFilenameTest", "Retrieved: $retrieved")
        assertEquals(value, retrieved)
    }
    
    @Test
    fun testDelegateWithNullFilename() = runTest {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val ksafe = KSafe(context, null)  // Explicitly passing null
        
        var myProperty: String by ksafe(defaultValue = "default", encrypted = false)
        
        Log.d("NullFilenameTest", "Initial delegate value: $myProperty")
        assertEquals("default", myProperty)
        
        myProperty = "new value"
        Log.d("NullFilenameTest", "After setting delegate: $myProperty")
        assertEquals("new value", myProperty)
    }
}