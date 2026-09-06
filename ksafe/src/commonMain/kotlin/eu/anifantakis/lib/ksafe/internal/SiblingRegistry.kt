package eu.anifantakis.lib.ksafe.internal

/** The live [KSafeCore]s of ONE physical store, so a store-wide wipe reaches every core's private caches. */
internal class SiblingRegistry {
    private val lock = KSafeInitLock()
    private val cores = ArrayList<KSafeCore>()

    fun register(core: KSafeCore) {
        lock.withLock { if (cores.none { it === core }) cores.add(core) }
    }

    fun unregister(core: KSafeCore) {
        lock.withLock { cores.removeAll { it === core } }
    }

    fun others(self: KSafeCore): List<KSafeCore> =
        lock.withLock { cores.filter { it !== self } }
}
