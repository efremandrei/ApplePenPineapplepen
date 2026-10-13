# v0.3.0 verification

The shipped APK is built with Android SDK tools directly because this workspace cannot download Gradle/Maven dependencies. The normal Gradle project and GitHub Actions workflow provide independent validation.

Verified locally:

- Java compilation against API 36, AAPT2 resource/manifest compilation, D8 for API 30+, alignment, and APK signature verification.
- 45 JUnit tests include bounded RESP/SMTP parsing, Redis PING/INFO and NOAUTH, PostgreSQL SSLRequest decline and TLS upgrade, SMTP EHLO/STARTTLS, protocol assignment scope, verified credentialed HTTPS, untrusted and identity-mismatched certificate blocking, reflected-token exclusion from text/HTML/JSON and serialized history, missing/cleared credentials, per-start credential handoff isolation, conservative TLS version evidence, and synthetic v0.1/v0.2 report compatibility.
- Tests use owned loopback fixtures only. No public destination was scanned.
- The delivered APK increments version code to 3, retains the original signing certificate, and disables debugging.

GitHub Actions runs Gradle unit tests, lint, and APK assembly, then an Android 16 emulator test of the shipped APK. The emulator creates a v0.2 report before installing v0.3, checks retained history, scans five owned protocol fixtures, verifies TLS version observations and that untrusted TLS never receives Authorization, and exercises rescan and PDF/HTML/JSON exports. Screenshots, exported reports, UI XML, and logcat are saved as workflow artifacts. The workflow's actual outcome is authoritative.

Positive trusted credentialed HTTPS and SMTP/PostgreSQL TLS upgrades are exercised by JVM fixtures. The Android emulator exercises credential blocking on untrusted TLS and protocol observations. Physical-device battery behavior and manufacturer-specific document providers are not yet verified. Live NVD availability is not a release gate; deterministic parser/lookup fixtures cover the candidate logic.

The shipped artifact is a development-signed universal APK. SHA-256 checksums are in downloads/SHA256SUMS. A production distribution signing/setup process remains separate from this development release.
