package eu.anifantakis.lib.ksafe.biometrics

// nanoTime() is monotonic, but its origin is arbitrary and can be negative; only differences are used.
internal actual fun biometricMonotonicNowMs(): Double = (System.nanoTime() / 1_000_000).toDouble()
