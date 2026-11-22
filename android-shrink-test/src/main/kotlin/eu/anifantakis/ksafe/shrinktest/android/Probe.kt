package eu.anifantakis.ksafe.shrinktest.android

import android.app.Instrumentation
import android.content.Context
import eu.anifantakis.lib.ksafe.KSafe
import eu.anifantakis.lib.ksafe.KSafeSecurityPolicy
import eu.anifantakis.lib.ksafe.getOrCreateSecret
import eu.anifantakis.lib.ksafe.hardwareIsolated
import eu.anifantakis.lib.ksafe.invoke
import eu.anifantakis.lib.ksafe.plain
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.serialization.json.Json
import java.security.MessageDigest

/**
 * One phase of the shrink test, in a process of its own. `write` stores the values under [KEYS] and
 * reads them back; `read` reads what an earlier `write` stored, maybe by the other build.
 *
 * Results are `fact.*` (must match between the minified and the unminified build), `link.*` (must
 * match between a write and the read after it) and `build.*` (checked by the script).
 */
class Probe(private val instrumentation: Instrumentation, private val expectedVersion: String?) {
    private val context: Context = instrumentation.targetContext.applicationContext
    private val results = LinkedHashMap<String, String>()
    private val failures = mutableListOf<String>()
    private val violations = mutableListOf<String>()

    val failed: List<String> get() = failures

    private fun fact(name: String, value: Any?) {
        results["fact.$name"] = value.toString()
    }

    private fun check(name: String, actual: Any?, expected: Any?) {
        if (actual != expected) failures += "$name: expected <$expected>, got <$actual>"
    }

    suspend fun run(phase: String): Map<String, String> {
        results["build.minified"] = (Prefs::class.java.name != SOURCE_NAME_OF_PREFS).toString()
        results["build.ksafeClass"] = KSafe::class.java.name
        results["phase"] = phase

        val ksafe = KSafe(
            context,
            fileName = STORE,
            securityPolicy = KSafeSecurityPolicy.WarnOnly.copy(onViolation = { violations += it.name }),
        )
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        try {
            when (phase) {
                "write" -> write(ksafe, scope)
                "read" -> Unit
                else -> error("Unknown phase '$phase'")
            }
            verify(ksafe, scope, "$phase.stored")
            results["link.secret.sha256"] = secretHash(ksafe)

            val rotation = ksafe.rotateKeys()
            fact("rotation", rotation)
            check("rotation.failed", rotation.failed, 0)
            verify(ksafe, scope, "$phase.rotated")
            check("secret after rotation", secretHash(ksafe), results["link.secret.sha256"])

            describe(ksafe)
        } finally {
            scope.cancel()
        }
        return results
    }

    private suspend fun write(ksafe: KSafe, scope: CoroutineScope) {
        ksafe.clearAll()

        val prefs = Prefs(ksafe, scope)
        prefs.counter = Values.COUNTER
        prefs.token = Values.TOKEN
        prefs.profile = Values.PROFILE
        prefs.theme = Theme.DARK
        prefs.mood.value = Values.MOOD
        writeLocalDelegate(ksafe)

        ksafe.put("user_id", Values.USER_ID)
        ksafe.put("shape_square", Values.SQUARE)
        ksafe.put("shape_triangle", Values.TRIANGLE)
        ksafe.put<Session>("session", Session.LoggedOut)
        ksafe.put("tier", Tier.SILVER)
        ksafe.put("theme_direct", Theme.DARK)
        ksafe.put("ids", Values.IDS)
        ksafe.put("addresses", Values.ADDRESSES)
        ksafe.put("profile_explicit", Values.PROFILE, Profile.serializer())
        ksafe.plain.put("plain_note", Values.PLAIN_NOTE)
        ksafe.hardwareIsolated.put("hw_pin", Values.HW_PIN)
        FlavorProbe.write(ksafe)

        // Writes commit in order, so once this returns the delegates' writes are on disk too.
        ksafe.put("sentinel", 1)
    }

    private fun writeLocalDelegate(ksafe: KSafe) {
        var visits by ksafe(0)
        visits = Values.VISITS
    }

    private fun readLocalDelegate(ksafe: KSafe): Int {
        val visits by ksafe(0)
        return visits
    }

    private suspend fun verify(ksafe: KSafe, scope: CoroutineScope, stage: String) {
        val prefs = Prefs(ksafe, scope)
        check("$stage counter (delegate)", prefs.counter, Values.COUNTER)
        check("$stage counter (getDirect)", ksafe.getDirect("counter", -1), Values.COUNTER)
        check("$stage counter (getFlow)", ksafe.getFlow("counter", -1).first(), Values.COUNTER)
        check("$stage counter (asFlow)", prefs.counterFlow.first(), Values.COUNTER)
        check("$stage token", ksafe.getDirect("token", ""), Values.TOKEN)
        check("$stage profile", ksafe.getDirect("profile", Values.EMPTY_PROFILE), Values.PROFILE)
        check("$stage theme", ksafe.getDirect("theme", Theme.LIGHT), Theme.DARK)
        check("$stage mood (getDirect)", ksafe.getDirect("mood", ""), Values.MOOD)
        check("$stage mood (asMutableStateFlow)", prefs.mood.value, Values.MOOD)
        check("$stage visits (local delegate)", readLocalDelegate(ksafe), Values.VISITS)
        check("$stage visits (getDirect)", ksafe.getDirect("visits", 0), Values.VISITS)
        check("$stage user_id", ksafe.getDirect("user_id", UserId(0L)), Values.USER_ID)
        check("$stage shape_square", ksafe.getDirect<Shape>("shape_square", Circle(0.0)), Values.SQUARE)
        check("$stage shape_triangle", ksafe.getDirect<Shape>("shape_triangle", Circle(0.0)), Values.TRIANGLE)
        check("$stage session", ksafe.getDirect<Session>("session", Session.LoggedIn("nobody")), Session.LoggedOut)
        check("$stage tier", ksafe.getDirect("tier", Tier.GOLD), Tier.SILVER)
        check("$stage theme_direct", ksafe.getDirect("theme_direct", Theme.LIGHT), Theme.DARK)
        check("$stage ids", ksafe.getDirect("ids", emptyList<UserId>()), Values.IDS)
        check("$stage addresses", ksafe.getDirect("addresses", emptyMap<String, Address>()), Values.ADDRESSES)
        check(
            "$stage profile_explicit",
            ksafe.get("profile_explicit", Values.EMPTY_PROFILE, Profile.serializer()),
            Values.PROFILE,
        )
        check("$stage plain_note", ksafe.get("plain_note", ""), Values.PLAIN_NOTE)
        check("$stage hw_pin", ksafe.get("hw_pin", ""), Values.HW_PIN)
        check("$stage sentinel", ksafe.get("sentinel", 0), 1)
        FlavorProbe.verify(ksafe, stage, ::check)
    }

    private suspend fun secretHash(ksafe: KSafe): String {
        val secret = ksafe.getOrCreateSecret("probe_db")
        check("secret size", secret.size, 32)
        return MessageDigest.getInstance("SHA-256").digest(secret).joinToString("") { "%02x".format(it) }
    }

    private suspend fun describe(ksafe: KSafe) {
        fact("version", KSafe.VERSION)
        check("KSafe.VERSION", KSafe.VERSION, expectedVersion)

        val info = ksafe.protectionInfo
        fact("protection.intendedLevel", info.intendedLevel)
        fact("protection.effectiveLevel", info.effectiveLevel)
        fact("protection.custody", info.custody)
        fact("protection.notes", info.notes.sorted())
        fact("protection.kSafeVersion", info.kSafeVersion)
        fact("protection.isEncryptionOperational", info.isEncryptionOperational)
        fact("deviceKeyStorages", ksafe.deviceKeyStorages.map { it.name }.sorted())
        fact("securityViolations", violations.sorted())

        for (key in KEYS + FlavorProbe.KEYS) {
            val keyInfo = ksafe.getKeyInfo(key)
            if (keyInfo == null) failures += "getKeyInfo(\"$key\") is null"
            fact("keyInfo.$key", keyInfo)
        }

        // What the plugin wrote into the serializers, read back after R8.
        val json = Json
        fact("json.profile", json.encodeToString(Values.PROFILE))
        fact("json.square", json.encodeToString(Values.SQUARE))
        fact("json.triangle", json.encodeToString(Values.TRIANGLE))
        fact("json.session", json.encodeToString<Session>(Session.LoggedOut))
        fact("json.tier", json.encodeToString(Tier.SILVER))
        fact("json.theme", json.encodeToString(Theme.DARK))
        fact("json.userId", json.encodeToString(Values.USER_ID))
        check("json.profile", json.encodeToString(Values.PROFILE), Values.PROFILE_JSON)
        check("json.square", json.encodeToString(Values.SQUARE), Values.SQUARE_JSON)
        check("json.triangle", json.encodeToString(Values.TRIANGLE), Values.TRIANGLE_JSON)
        check("json.session", json.encodeToString<Session>(Session.LoggedOut), Values.SESSION_JSON)
        check("json.tier", json.encodeToString(Tier.SILVER), "\"silver\"")
        check("json.theme", json.encodeToString(Theme.DARK), "\"DARK\"")
        check("json.userId", json.encodeToString(Values.USER_ID), "9001")

        FlavorProbe.describe(instrumentation, ::fact, ::check)
    }

    companion object {
        const val STORE = "shrinkprobe"

        // Built at run time, so no shrinker can rewrite it along with the class it names.
        private val SOURCE_NAME_OF_PREFS = listOf("eu", "anifantakis", "ksafe", "shrinktest", "android", "Prefs")
            .joinToString(".")

        private val KEYS = listOf(
            "counter", "token", "profile", "theme", "mood", "visits", "user_id", "shape_square",
            "shape_triangle", "session", "tier", "theme_direct", "ids", "addresses",
            "profile_explicit", "plain_note", "hw_pin", "sentinel",
        )
    }
}
