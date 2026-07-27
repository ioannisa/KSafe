package eu.anifantakis.lib.ksafe

/**
 * Encodes [num] as base-26 lowercase letters (1→"a", 27→"aa"). KSafe store file names must match
 * `[a-z][a-z0-9_]*`, so every suite that derives a unique name from a counter or a timestamp needs
 * exactly this. Pure Kotlin, so one copy serves jvmTest, webTest and androidDeviceTest.
 */
internal fun numberToLetters(num: Long): String {
    var n = num
    val sb = StringBuilder()
    while (n > 0) {
        n-- // 0-based: 'a' is 0, not 1.
        sb.insert(0, ('a' + (n % 26).toInt()))
        n /= 26
    }
    return if (sb.isEmpty()) "a" else sb.toString()
}
