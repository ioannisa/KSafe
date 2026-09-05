package eu.anifantakis.lib.ksafe.internal

import java.util.concurrent.ConcurrentHashMap

// Frozen layout shared by the two javax.crypto engines: every persisted ciphertext is `IV ‖ ct+tag`
// with these sizes, so changing either number — or changing one engine only — orphans existing data.
internal object JvmAesGcm {
    const val TAG_LENGTH_BITS: Int = 128

    const val IV_LENGTH_BYTES: Int = 12

    const val TRANSFORMATION: String = "AES/GCM/NoPadding"
}

// Lock objects rather than intern()ed alias strings: a dynamic key set would grow the string pool
// without bound.
internal class AliasLocks {
    private val locks = ConcurrentHashMap<String, Any>()

    fun forAlias(alias: String): Any = locks.computeIfAbsent(alias) { Any() }
}
