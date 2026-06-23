# Contributing to KSafe

Thank you for investing time in KSafe. Contributions of all kinds are welcome: bug reports, documentation improvements, examples, tests, performance work, platform support, and code changes.

KSafe aims to provide a dependable Kotlin Multiplatform persistence API for both ordinary application state and sensitive values. Contributions should preserve that goal: a small, idiomatic developer-facing API backed by clear platform behavior and robust defaults.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before You Start

Please search existing issues and pull requests before opening a new one. A short discussion before substantial implementation work is especially useful for:

- New public APIs or behavior changes.
- New platforms or platform-specific persistence/key-protection mechanisms.
- Changes affecting encrypted data formats, migrations, or compatibility.
- New Gradle modules, dependencies, or transitive dependencies.

For a proposed feature, open a GitHub issue that explains the developer problem, expected behavior, target platforms, and a rough API sketch where useful. This helps avoid building an API that conflicts with KSafe's architecture or release plan.

## Reporting Bugs

Open a GitHub issue with enough information to reproduce the problem reliably. A useful report includes:

- KSafe version and Kotlin version.
- Gradle, Android Gradle Plugin, and Compose versions where relevant.
- Target platform(s), OS version, browser/runtime, and device or emulator details.
- A minimal reproducible sample or repository.
- Expected behavior, actual behavior, and the full exception/stack trace.
- Whether the issue occurs in plain mode, encrypted mode, or both.

Never include real tokens, passwords, key material, personally identifiable information, or production persistence files in a public issue.

## Reporting Security Issues

Do **not** report potential security vulnerabilities in a public GitHub issue.

Follow the private disclosure process in [SECURITY.md](SECURITY.md). Include a clear description, affected versions/platforms, reproduction steps or proof of concept, potential impact, and any suggested mitigation.

## Development Setup

1. Fork the repository and create a feature branch from the default branch.
2. Use the JDK and Kotlin/Gradle versions configured by the repository.
3. Import the project into Android Studio or IntelliJ IDEA.
4. Run the relevant checks before opening a pull request.

Typical commands are:

```bash
./gradlew check
./gradlew test
```

Run platform-specific checks or sample applications when your change affects a particular target. For example, changes to Android keystore behavior, Apple Keychain integration, desktop key custody, browser storage, or Web Crypto should be exercised on the affected platform—not only through JVM tests.

## Pull Request Guidelines

Keep pull requests focused. A pull request should solve one coherent problem and avoid unrelated formatting, refactoring, or dependency upgrades.

Please:

- Explain the problem and the chosen solution in the pull request description.
- Link the relevant issue when one exists.
- Add or update tests for behavior changes and bug fixes.
- Update documentation, KDoc, samples, and changelog material when users will observe a new or changed capability.
- State which KMP targets you tested.
- Call out compatibility, migration, storage-format, and security implications explicitly.
- Avoid committing generated build output, IDE metadata, secrets, or local signing files.

Small, reviewable pull requests are easier to validate across KSafe's supported targets and are more likely to be merged quickly.

## API and Compatibility Expectations

KSafe is used in application persistence paths, so public API changes require particular care.

- Prefer additive changes over breaking changes.
- Do not remove or rename a public API without a documented migration path and a deprecation period where practical.
- Preserve source and binary compatibility when possible.
- Do not change encrypted storage, key derivation, serialization, or migration behavior without tests and a documented compatibility plan.
- Do not weaken the default protection model for convenience. A new fallback must be explicit, observable, and documented.
- Keep behavior consistent across platforms unless a platform limitation makes that impossible; in that case, surface the distinction clearly in documentation and diagnostics.

## Coding Style

Follow the existing Kotlin style and project conventions. In particular:

- Prefer clear, idiomatic Kotlin and simple control flow.
- Keep public APIs small and intentional.
- Use explicit nullable types where a `null` default is required.
- Prefer immutable data models and `copy()` updates for typed settings.
- Avoid `runBlocking` for persistence writes.
- Do not wrap KSafe delegates in `MutableStateFlow`; use KSafe's provided reactive APIs where appropriate.
- Keep Android-specific code on the Android side and use `applicationContext`, never an Activity context, when constructing `KSafe`.

Add KDoc for public API additions, particularly when platform support, protection semantics, threading, or initialization timing may not be obvious.

## Testing Expectations

Every behavior change should have appropriate automated coverage. Depending on the contribution, this may include common tests, platform tests, integration tests, and manual verification.

Pay special attention to:

- Serialization and migration behavior.
- Plain versus encrypted writes.
- Key-storage and protection reporting.
- Concurrency and reactive updates.
- Application restart and persistence recovery.
- Platform-specific secure-storage limitations and fallbacks.
- Web initialization requirements, including `awaitCacheReady()` before synchronous encrypted reads.

Tests should not depend on production secrets or external services unless the repository explicitly provides a controlled test setup.

## Documentation and Examples

Documentation is part of the product. Please update it when a change affects setup, usage, platform support, security assumptions, migration, or troubleshooting.

Examples should use the recommended delegate-first API where applicable:

```kotlin
var token by ksafe("")
var launchCount by ksafe(0, mode = KSafeWriteMode.Plain)
```

For typed settings, favor immutable models:

```kotlin
data class Settings(
    val theme: String = "system"
)

var settings by ksafe(
    Settings(),
    mode = KSafeWriteMode.Plain
)

settings = settings.copy(theme = "dark")
```

Avoid presenting deprecated APIs or patterns that bypass KSafe's documented initialization and protection guidance.

## Review and Merge Process

The maintainer reviews contributions as time permits. Review may cover API design, correctness, security posture, tests, documentation, platform compatibility, and long-term maintainability.

A contribution may be revised, split, postponed, or declined when it does not fit the project roadmap or would make the library harder to support. This is not a judgment of the contributor; it is necessary to keep KSafe reliable and coherent across platforms.

## License

By submitting a contribution, you agree that your contribution is licensed under the same license as the project: [Apache License 2.0](LICENSE).
