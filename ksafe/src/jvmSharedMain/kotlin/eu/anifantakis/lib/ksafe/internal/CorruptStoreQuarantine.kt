package eu.anifantakis.lib.ksafe.internal

import java.io.File

// Copies an unparseable store file aside before DataStore's corruption handler continues from
// empty, so the bytes outlive the next write; a failed copy is swallowed to keep the store readable.
internal fun quarantineCorruptStoreFile(file: File) {
    runCatching {
        file.copyTo(
            File(file.parentFile, corruptQuarantineName(file.name, System.currentTimeMillis())),
            overwrite = false,
        )
    }
}

// The java.io.File half; Apple drives NSFileManager and calls the neutral overload directly.
internal fun sweepCorruptQuarantineCopies(storeFile: File) {
    val dir = storeFile.absoluteFile.parentFile ?: return
    sweepCorruptQuarantineCopies(
        storeFileName = storeFile.name,
        listNames = { dir.listFiles()?.map { it.name }.orEmpty() },
        delete = { name -> File(dir, name).delete() },
    )
}
