package eu.anifantakis.lib.ksafe.biometrics

/** Builds the JNA bridge [name] on first touch, degrading to `null` when its libraries are missing;
 *  permissive calls then pass through and strict ones refuse. Lazy, so the first JNA touch happens
 *  inside the catch. */
internal fun <T : Any> lazyNativeBridge(name: String, create: () -> T): Lazy<T?> = lazy {
    try {
        create()
    } catch (t: Throwable) {
        System.err.println(
            "KSafe biometrics: $name bridge unavailable (${t.message}); " +
                "verifyBiometric passes through (allowDeviceCredentialFallback=true) or refuses (false)."
        )
        null
    }
}
