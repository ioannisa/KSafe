package eu.anifantakis.ksafe.compose

/**
 * Encodes [num] as base-26 lowercase letters (1→"a", 27→"aa"), for the unique store file names
 * KSafe requires (`[a-z][a-z0-9_]*`). A separate copy from `:ksafe`'s: Gradle test source sets are
 * not published across module boundaries, so `:ksafe`'s commonTest helper is unreachable here.
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
