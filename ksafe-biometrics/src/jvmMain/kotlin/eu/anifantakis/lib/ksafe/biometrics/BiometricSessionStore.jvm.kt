package eu.anifantakis.lib.ksafe.biometrics

// nanoTime() never goes backward, but its origin is arbitrary and may be negative — only
// differences are meaningful, which is why the store keys freshness on entry presence.
internal actual fun biometricMonotonicNowMs(): Double = (System.nanoTime() / 1_000_000).toDouble()
