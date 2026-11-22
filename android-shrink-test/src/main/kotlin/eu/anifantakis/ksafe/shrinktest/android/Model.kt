package eu.anifantakis.ksafe.shrinktest.android

import eu.anifantakis.lib.ksafe.KSafe
import eu.anifantakis.lib.ksafe.asFlow
import eu.anifantakis.lib.ksafe.asMutableStateFlow
import eu.anifantakis.lib.ksafe.encrypted
import eu.anifantakis.lib.ksafe.invoke
import kotlinx.coroutines.CoroutineScope
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
enum class Tier {
    @SerialName("gold") GOLD,
    @SerialName("silver") SILVER,
}

// No @Serializable: the serialization plugin builds its serializer at the call site.
enum class Theme { DARK, LIGHT }

@Serializable
data class Address(val city: String, val zip: String? = null)

@Serializable
data class Profile(
    val name: String,
    val age: Int,
    val address: Address?,
    val tags: List<String>,
    val tier: Tier,
)

@Serializable
@JvmInline
value class UserId(val raw: Long)

@Serializable
sealed interface Shape

@Serializable
@SerialName("square")
data class Square(val side: Int) : Shape

@Serializable
@SerialName("circle")
data class Circle(val radius: Double) : Shape

// No @SerialName: its discriminator is the class's source name, which R8 must not change.
@Serializable
data class Triangle(val a: Int, val b: Int, val c: Int) : Shape

@Serializable
sealed interface Session {
    @Serializable
    @SerialName("logged_out")
    data object LoggedOut : Session

    @Serializable
    @SerialName("logged_in")
    data class LoggedIn(val user: String) : Session
}

// Delegates take the property's name as their key, so R8 must leave those names alone.
class Prefs(ksafe: KSafe, scope: CoroutineScope) {
    var counter by ksafe(0)
    var token by ksafe.encrypted("")
    var profile by ksafe(Values.EMPTY_PROFILE)
    var theme by ksafe(Theme.LIGHT)
    val counterFlow by ksafe.asFlow(-1, key = "counter")
    val mood by ksafe.asMutableStateFlow("neutral", scope)
}

object Values {
    const val COUNTER = 42
    const val TOKEN = "tok-5f3a"
    const val VISITS = 7
    const val MOOD = "calm"
    const val PLAIN_NOTE = "visible"
    const val HW_PIN = "4321"

    val EMPTY_PROFILE = Profile("", 0, null, emptyList(), Tier.GOLD)
    val PROFILE = Profile("Ada", 36, Address("Athens", "10558"), listOf("admin", "beta"), Tier.GOLD)
    val USER_ID = UserId(9001L)
    val SQUARE: Shape = Square(3)
    val TRIANGLE: Shape = Triangle(3, 4, 5)
    val IDS = listOf(UserId(1L), UserId(2L), UserId(3L))
    val ADDRESSES = mapOf("home" to Address("Athens", "10558"), "work" to Address("Berlin"))

    // What the serialization plugin writes for these values, whatever R8 renamed.
    const val PROFILE_JSON =
        """{"name":"Ada","age":36,"address":{"city":"Athens","zip":"10558"},"tags":["admin","beta"],"tier":"gold"}"""
    const val SQUARE_JSON = """{"type":"square","side":3}"""
    const val TRIANGLE_JSON =
        """{"type":"eu.anifantakis.ksafe.shrinktest.android.Triangle","a":3,"b":4,"c":5}"""
    const val SESSION_JSON = """{"type":"logged_out"}"""
}
