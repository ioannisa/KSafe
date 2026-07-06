package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * FEEDBACK_4 H8: getFlowRaw's .map calls engine.decryptSuspend — on Android a synchronous
 * Binder round-trip to the Keystore daemon — and getStateFlow collects on the caller's scope
 * (viewModelScope ⇒ Dispatchers.Main.immediate). Without a flowOn the decrypt ran on the
 * collector's dispatcher (the main thread) on every snapshot emission → ANR. getFlowRaw now
 * appends .flowOn(Dispatchers.Default), matching getRaw's withContext(Dispatchers.Default), so
 * the blocking keystore IPC never runs on the collector's dispatcher.
 */
class JvmFlowDecryptDispatcherTest {

    /** XOR engine that records the thread its decrypt runs on. */
    private class ThreadRecordingEngine : KSafeEncryption {
        val decryptThreads = CopyOnWriteArrayList<String>()
        private val xor = FakeEncryption()
        override fun encrypt(identifier: String, data: ByteArray, hardwareIsolated: Boolean, requireUnlockedDevice: Boolean?): ByteArray =
            xor.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice)
        override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray {
            decryptThreads.add(Thread.currentThread().name)
            return xor.decrypt(identifier, data)
        }
        override fun deleteKey(identifier: String) {}
    }

    @Test
    fun getFlow_decryptsOnDefaultDispatcher_notTheCollectorThread() {
        val engine = ThreadRecordingEngine()
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            lazyLoad = true,
            testEngine = engine,
        )
        runBlocking { ksafe.put("k", "v", KSafeWriteMode.Encrypted()) }

        // A single-threaded "main-like" dispatcher stands in for viewModelScope's
        // Dispatchers.Main.immediate. Collecting the flow here would run the decrypt on this
        // thread without flowOn; with flowOn it runs on a Dispatchers.Default worker.
        val collector = Executors.newSingleThreadExecutor { r -> Thread(r, "ksafe-test-collector") }
        val collectorDispatcher = collector.asCoroutineDispatcher()
        try {
            runBlocking {
                val job = launch(collectorDispatcher) {
                    ksafe.getFlow("k", "def").first { it == "v" }
                }
                job.join()
            }
            assertTrue(engine.decryptThreads.isNotEmpty(), "precondition: the flow decrypted at least one snapshot")
            assertTrue(
                engine.decryptThreads.all { it.contains("DefaultDispatcher") },
                "getFlow must decrypt on Dispatchers.Default, never the collector's dispatcher (H8 ANR). Threads: ${engine.decryptThreads}",
            )
        } finally {
            collectorDispatcher.close()
            ksafe.close()
        }
    }
}
