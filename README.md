# ApplePen

A native Android app that assesses one destination IP and produces an evidence-based security report. Runs directly on the phone without root, an account, or a remote scanner.

## Install

Download [ApplePen-v0.1.0.apk](downloads/ApplePen-v0.1.0.apk) from this repository. Open the APK on Android and allow installation from that source when prompted. Requires **Android 11 or newer**. This initial APK is signed with a development key.

The app label is **ApplePen**; the package is `info.hen14.applepen`.

## Start an assessment

1. Connect the phone to a network or VPN that can reach the target.
2. Enter a single IPv4 or IPv6 address. Subnets, URLs, and hostname-only destinations are not accepted.
3. Optionally enter the intended hostname for HTTP Host and TLS SNI/certificate checks. This hostname does not change the socket destination.
4. Choose Quick, Standard, Full TCP, or custom ports. Adjust timeouts and concurrency if needed.
5. Confirm that you own the target or have permission to assess it, then start.
6. Review findings and service evidence. Export PDF, HTML, or JSON through Android's document picker.

A visible foreground service and notification allow scans to continue when you switch apps. Stop from the app or the notification. The 20-minute budget produces a partial report when exceeded. Permission to show notifications is optional for launching the scan; Android still exposes the foreground task through its system UI.

## Implemented checks

| Capability | Actual behavior |
|---|---|
| TCP discovery | Connection scans with bounded concurrency; distinguishes open, refused, timed out, and connection errors. |
| Service observation | Greeting reads on common SSH, FTP, Telnet, and mail ports. Ports are never identified from their number alone. |
| SSH | Reports an observed SSH banner and flags an advertised SSH 1.5 protocol. No login attempts. |
| FTP / Telnet | Reports observed FTP exposure or a possible Telnet greeting with contextual impact. No credential attempts. |
| HTTP / HTTPS | One root request on configured common web ports, with response limits. No redirect, link, or resource traversal. |
| Web configuration | Context-aware HTML security headers, Secure/HttpOnly cookie attributes, product headers, and suspected directory listings. Cookie values are redacted. |
| TLS | Negotiated protocol/cipher, certificate validity, subject alternative name matching, and trust against the phone's system trust store. |
| Findings | Severity, confidence, observed/suspected status, evidence, impact, remediation, and references. |
| Reporting | Local history for 30 reports; paginated PDF, self-contained HTML, and schema-versioned JSON exports. |
| Interrupted runs | Marks a saved run as interrupted after process death. Completed/cancelled runs are retained. |

All assessments are unauthenticated. A scan describes exposure from the phone's active routing at scan start. Open ports alone are not vulnerabilities; timeouts are inconclusive. A report with no findings does not demonstrate that the system is secure.

HTTP observation ports: `80, 3000, 5000, 5985, 8000, 8008, 8080, 8081, 8888, 9000, 9090, 9200`. HTTPS observation ports: `443, 2376, 5986, 8443`. Certificate-only TLS checks also cover `465, 636, 993, 995`. Other TCP ports can be scanned but receive connection observations only unless a greeting check is implemented. Service inspection is capped at 64 open ports and the report records this limit. The on-screen view shows up to 200 findings/services; exports contain the full result.

## Scope of v0.1

This release is an automated network security assessment, not a replacement for a complete penetration test. It does **not** perform CVE database matching, exhaustive TLS cipher enumeration, UDP/raw-packet scans, OS fingerprinting, exploit execution, password attacks, authenticated checks, or application business-logic testing. Failed handshakes are not taken as proof of secure TLS settings. Banner versions are never reported as verified vulnerabilities.

Future work: protocol modules on custom ports, maintained CVE applicability rules, authenticated read-only checks, scan comparison, and an optional privately hosted Linux scanning engine.

## Privacy and permissions

No analytics, ads, account, or cloud upload is included. Reports reside in private app storage; backup is disabled. Exports go only to a destination chosen through Android's document picker. Uninstalling removes internal history.

`INTERNET` and network-state access support assessment and network-viewpoint reporting. A bounded wake lock keeps the CPU available during a scan. A `specialUse` foreground service covers user-initiated assessments with progress and cancellation. Android 13+ notification permission is requested. The manifest also declares the Android 17 local-network permission for future targeting; this release targets API 36, and includes a permission request path when upgraded to target API 37.

TLS inspection uses an isolated capture trust manager to observe a presented certificate, then explicitly checks its validity, identity, and system trust. It does not alter global trust or any other app's connections.

## Build and test

Open in Android Studio, or use JDK 17 and an Android SDK:

```bash
./gradlew testDebugUnitTest lintDebug assembleDebug
```

The project uses AGP 8.12.2, Gradle 8.13, compile/target API 36, and minimum API 30. There are no third-party runtime dependencies. Tests use JUnit 4.13.2. GitHub Actions builds an APK and uploads test/lint reports for pushes and pull requests, with read-only repository permissions.

For environments with SDK tools installed but Maven access unavailable:

```bash
ANDROID_HOME=/path/to/android-sdk bash tools/build-local.sh
JUNIT_JAR=/path/to/junit-4.13.2.jar HAMCREST_JAR=/path/to/hamcrest-core-1.3.jar bash tools/test-core.sh
```

The SDK-only script requires platform API 36 and build-tools 36.0.0; it compiles resources, Java classes, DEX, aligns and development-signs the APK. Its key stays in the ignored `app/build` directory. Debug keys from different build environments differ, so switching APK sources may require uninstalling the old build first; export reports before uninstalling.

## Structure

- `app/.../core`: platform-independent configuration, scanning, response parsing, findings, certificate matching, and report rendering.
- `ScanService`: foreground execution, cancellation, network viewpoint, and lifecycle handling.
- `MainActivity`: scan settings, progress, history, evidence review, and document exports.
- `ReportStore`: atomic private report storage.
- `PdfExporter`: Android-native paginated PDF export.
- `app/src/test`: local fixtures and security/correctness regression tests; no public targets are contacted.

See [VALIDATION.md](VALIDATION.md) for the shipped build's verification and known limitations.
