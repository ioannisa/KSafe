# Architecture: Hybrid "Hot Cache"

KSafe 1.2.0 introduced a completely rewritten core architecture focusing on zero-latency UI performance.

### How It Works

**Before (v1.1.x):** Every `getDirect()` call triggered a blocking disk read and decryption on the calling thread.

**Now (v1.2.0):** Data is preloaded asynchronously on initialization. `getDirect()` performs an **Atomic Memory Lookup (O(1))**, returning instantly.

**Safety:** If data is accessed before the preload finishes, the library automatically falls back to a blocking read.

### Optimistic Updates

`putDirect()` updates the in-memory cache **immediately**, allowing your UI to reflect changes instantly while disk encryption happens in the background.

### Encryption Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        KSafe API                            │
│         (get, put, getDirect, putDirect, delete)            │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                      KSafeConfig                            │
│                        (keySize)                            │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│               KSafeEncryption Interface                     │
│            encrypt() / decrypt() / deleteKey()              │
└─────────────────────────┬───────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┬───────────────┐
          ▼               ▼               ▼               ▼
┌─────────────────┐ ┌───────────────┐ ┌─────────────┐ ┌─────────────┐
│    Android      │ │     iOS       │ │     JVM     │ │    WASM     │
│    Keystore     │ │   Keychain    │ │  Software   │ │  WebCrypto  │
│   Encryption    │ │  Encryption   │ │  Encryption │ │  Encryption │
└─────────────────┘ └───────────────┘ └─────────────┘ └─────────────┘
```
