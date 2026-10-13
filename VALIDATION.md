# v0.1.0 verification

The initial APK is built with the Android SDK tools directly because this workspace cannot download Gradle/Maven dependencies. The normal Gradle project and GitHub Actions workflow are included for standard development.

Verified locally:

- Java source compilation against Android API 36.
- Resource and manifest compilation with AAPT2.
- DEX generation with D8 for API 30+.
- APK alignment and APK signature verification.
- 15 JUnit regression tests covering literal-IP scope, host-header injection rejection, port validation/deduplication, IPv6 Host formatting, certificate wildcard boundaries, HTTP response parsing, contextual web checks, cookie redaction, escaping, local open/refused TCP ports, pinned-IP HTTP Host handling, non-followed redirects, and pre-cancellation. A local TLS fixture additionally verifies a self-signed chain finding, successful HTTPS observation, and matching DNS/IP certificate names without a false identity-mismatch finding.

The network integration tests use local loopback fixtures only. No public destination was scanned.

Not yet verified on a physical Android device: foreground-service behavior on manufacturer-specific battery settings, document-provider exports, PDF appearance, and UI interactions. No emulator or phone was attached to this workspace. The Gradle/lint CI result is recorded separately in GitHub Actions; an SDK-only build does not establish that lint has passed.

The shipped artifact is a development-signed universal APK with no native ABI dependency. Its SHA-256 checksum is in `downloads/SHA256SUMS`.
