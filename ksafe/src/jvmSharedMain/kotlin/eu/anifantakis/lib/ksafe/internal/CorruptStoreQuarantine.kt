package eu.anifantakis.lib.ksafe.internal

import java.io.File

/**
 * Copies an unparseable store file aside as `<name>.corrupt-<timestamp>` before DataStore's
 * corruption handler continues from empty, so the bytes stay recoverable instead of being
 * overwritten by the next write. Best-effort: a failed copy must not turn a recoverable corruption
 * back into a read that throws forever.
 *
 * The name comes from [corruptQuarantineName] because it is load-bearing in both directions —
 * `clearAll()` sweeps quarantine copies by it, as they still hold decryptable ciphertext.
 */
internal fun quarantineCorruptStoreFile(file: File) {
    runCatching {
        file.copyTo(
            File(file.parentFile, corruptQuarantineName(file.name, System.currentTimeMillis())),
            overwrite = false,
        )
    }
}

/**
 * The `java.io.File` half of [sweepCorruptQuarantineCopies], beside the writer whose output it
 * reclaims. Android and JVM both reach a store file's own directory this way; Apple drives
 * `NSFileManager` and calls the platform-neutral overload directly.
 */
internal fun sweepCorruptQuarantineCopies(storeFile: File) {
    val dir = storeFile.absoluteFile.parentFile ?: return
    sweepCorruptQuarantineCopies(
        storeFileName = storeFile.name,
        listNames = { dir.listFiles()?.map { it.name }.orEmpty() },
        delete = { name -> File(dir, name).delete() },
    )
}
