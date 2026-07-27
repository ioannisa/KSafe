package eu.anifantakis.lib.ksafe.biometrics

// webBioMonotonicNowMs is `performance.now()`, actualized per web leaf (js / wasmJs).
internal actual fun biometricMonotonicNowMs(): Double = webBioMonotonicNowMs()
