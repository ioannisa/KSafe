package eu.anifantakis.lib.ksafe.biometrics

// Must not go backward and must keep counting during sleep; nanoTime() freezes on SoC suspend,
// so use elapsedRealtime() (CLOCK_BOOTTIME).
internal actual fun biometricMonotonicNowMs(): Double =
    android.os.SystemClock.elapsedRealtime().toDouble()
