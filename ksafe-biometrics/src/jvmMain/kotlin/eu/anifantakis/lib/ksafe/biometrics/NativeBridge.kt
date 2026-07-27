package eu.anifantakis.lib.ksafe.biometrics

/**
 * Builds the JNA bridge named [name] on first touch, degrading to `null` — the documented
 * pass-through — when its platform libraries are missing or fail to load.
 *
 * Lazy so that merely loading the owning object on another OS never touches those libraries,
 * and so the first touch of any JNA class stays inside the catch.
 */
internal fun <T : Any> lazyNativeBridge(name: String, create: () -> T): Lazy<T?> = lazy {
    try {
        create()
    } catch (t: Throwable) {
        System.err.println(
            "KSafe biometrics: $name bridge unavailable (${t.message}); " +
                "verifyBiometric falls back to pass-through."
        )
        null
    }
}
