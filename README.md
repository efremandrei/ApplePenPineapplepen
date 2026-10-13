# ApplePen

A native Android app that assesses one destination IP and produces an evidence-based security report. Runs directly on the phone without root, an account, or a remote scanner.

## Install

Download [ApplePen-v0.3.0.apk](downloads/ApplePen-v0.3.0.apk) from this repository. Open the APK on Android and allow installation from that source when prompted. Requires **Android 11 or newer**. The APK uses the same development signing key as the shipped v0.1.0/v0.2.0 APKs, so it can be installed as an update while retaining local history.

The app label is **ApplePen**; the package is `info.hen14.applepen`.

## Start an assessment

1. Connect the phone to a network or VPN that can reach the target.
2. Enter a single IPv4 or IPv6 address. Subnets, URLs, and hostname-only destinations are not accepted.
3. Optionally enter the intended hostname for HTTP Host and TLS SNI/certificate checks. This hostname does not change the socket destination.
4. Choose Quick, Standard, Full TCP, or custom ports. Adjust timeouts and concurrency if needed. Assign additional HTTP/HTTPS ports when a web service uses a nonstandard port; those ports must also be selected for TCP scanning.
5. Enable read-only Redis/PostgreSQL/SMTP probes as needed. Assign nonstandard Redis/PostgreSQL ports within the TCP selection. Optional direct TLS version probes add four handshakes per TLS listener.
6. For one credentialed root-page check, select Basic or Bearer, a selected HTTPS port, and your credential. System trust and identity verification must succeed before Authorization is sent. Credentials must be re-entered for each scan.
7. Optionally enable NVD version lookup. Product/version data is sent to NVD; the target IP and hostname are not included in queries. Lookups may add tens of seconds.
8. Confirm that you own the target or have permission to assess it, then start.
9. Review findings and service evidence. Filter high/critical findings or potential CVEs. Export PDF, HTML, or JSON through Android's document picker.

A visible foreground service and notification allow scans to continue when you switch apps. Stop from the app or the notification. The 20-minute budget produces a partial report when exceeded. Permission to show notifications is optional for launching the scan; Android still exposes the foreground task through its system UI.

## Implemented checks

| Capability | Actual behavior |
|---|---|
| TCP discovery | Connection scans with bounded concurrency; distinguishes open, refused, timed out, and connection errors. |
| Service observation | Receive-only greeting reads on other inspected TCP ports, including nonstandard SSH/FTP ports. Identifies SSH and recognizable FTP/SMTP/POP/IMAP greetings. No protocol is confirmed solely by its port number. |
| SSH | Reports an observed SSH banner and flags an advertised SSH 1.5 protocol. No login attempts. |
| FTP / Telnet | Reports observed FTP exposure or a possible Telnet greeting with contextual impact. No credential attempts. |
| HTTP / HTTPS | One root request on common web ports and explicitly assigned additional ports, with response limits. No redirect, link, or resource traversal. |
| Web configuration | Context-aware HTML security headers, Secure/HttpOnly cookie attributes, product headers, and suspected directory listings. Cookie values are redacted. |
| TLS | Negotiated protocol/cipher, certificate validity, subject alternative name matching, and phone system trust. Optional dedicated TLS 1.0/1.1/1.2/1.3 probes on direct TLS listeners. Only successful handshakes establish support; failed/client-disabled versions remain inconclusive. |
| Redis | PING followed by INFO server on 6379 or explicitly assigned ports. Reports unauthenticated server-version disclosure with contextual Low severity. Access restrictions are observations. No AUTH, key reads, writes, or other commands. |
| PostgreSQL | An eight-byte SSLRequest on 5432 or assigned ports; observes S/N and inspects the certificate after S. No startup/login, queries, or role checks. A declined negotiation is contextual evidence, not proof of plaintext database access. |
| SMTP | EHLO and advertised STARTTLS on selected 25/587 or recognized SMTP greetings on other ports. Certificate inspection after upgrade. No AUTH, MAIL, RCPT, DATA, relay testing, or email delivery. Missing STARTTLS is informational. |
| Credentialed HTTPS | One GET / on one explicitly selected HTTPS port with supplied Basic or Bearer credentials. Normal system trust and endpoint identity verification, pinned destination IP, no redirects. Reports numeric status and header/cookie checks; response text, cookie names, and arbitrary header values are discarded. A 2xx response alone does not establish credential acceptance. |
| Findings | Severity, confidence, observed/suspected status, evidence, impact, remediation, and references. |
| Optional CVE candidates | Version-bearing OpenSSH, nginx, Apache HTTP Server, and vsftpd fingerprints are resolved against NVD's CPE dictionary. Exact non-deprecated version matches are queried through the CVE API. Records are labeled Potential CVE with Low confidence, even when NVD's CVSS severity is high. |
| Reporting | Local history for 30 reports; paginated PDF, self-contained HTML, and schema-versioned JSON exports. |
| Comparison and rescan | Reuse a saved configuration from History. Compare two completed scans for the same target, port/protocol scope, CVE setting, and connection type. Save/export comparisons. Missing findings are labeled Not observed again, not Fixed. Credentialed reports cannot be compared because account identity is deliberately not retained. |
| Interrupted runs | Marks a saved run as interrupted after process death. Completed/cancelled runs are retained. |

By default, assessments send no credentials. The optional HTTPS check uses only credentials explicitly supplied for that scan. A scan describes exposure from the phone's active routing at scan start. Open ports alone are not vulnerabilities; timeouts are inconclusive. A report with no findings does not demonstrate that the system is secure.

HTTP observation ports: `80, 3000, 5000, 5985, 8000, 8008, 8080, 8081, 8888, 9000, 9090, 9200`. HTTPS observation ports: `443, 2376, 5986, 8443`. Certificate-only TLS checks also cover `465, 636, 993, 995`. Up to 32 additional protocol-port assignments are supported. With protocol checks enabled, Redis/PostgreSQL assignments receive the probes above; SMTP is checked on 25/587 or recognizable greetings. Other unassigned ports receive greeting reads. Web/known TLS and protocol checks are prioritized within the 64-open-port inspection cap. The on-screen view shows up to 200 findings/services; exports contain the full result.

## NVD lookup behavior

Lookup is off by default and requires no API key. It uses the official [NVD CPE API](https://nvd.nist.gov/developers/products) and [CVE API](https://nvd.nist.gov/developers/vulnerabilities). A bounded dictionary search checks vendor, product, version, and update identifiers before using `cpeName` and `isVulnerable` filters. Rejected CVEs and deprecated dictionary entries are excluded. No broad keyword result is treated as proof of a vulnerable installation.

Queries are spaced at least 7 seconds apart, with at most 3 distinct product/version pairs per scan and one 20-record CVE page per product. Responses are bounded, strictly parsed, and cached for 24 hours with source timestamps in reports. Missing dictionary matches, outages, timeouts, rate limits, and capped results are recorded as coverage limitations. Empty results never establish that a service is secure. Vendor backports, spoofed banners, and configuration prerequisites require separate verification.

## Scope of v0.3

This release is an automated network security assessment. It does **not** perform exhaustive TLS cipher enumeration, UDP/raw-packet scans, OS fingerprinting, exploit execution, password attacks, database/key access, authenticated crawling, or application business-logic testing. Failed handshakes are not taken as proof of secure TLS settings. Banner versions and CVE candidates are never reported as verified vulnerabilities.

Future work: stronger CVE configuration/range applicability checks, more protocol modules, authenticated endpoint selection, and an optional privately hosted Linux scanning engine.

## Privacy and permissions

No analytics, ads, account, or report upload is included. Reports reside in private app storage; backup is disabled. Exports go only to a destination chosen through Android's document picker. Optional NVD lookup sends software identifiers to NVD and uses normal HTTPS validation. Uninstalling removes internal history and the local NVD cache.

`INTERNET` and network-state access support assessment and network-viewpoint reporting. A bounded wake lock keeps the CPU available during a scan. A `specialUse` foreground service covers user-initiated assessments with progress and cancellation. Android 13+ notification permission is requested. The manifest also declares the Android 17 local-network permission for future targeting; this release targets API 36, and includes a permission request path when upgraded to target API 37.

TLS inspection uses an isolated capture trust manager to observe a presented certificate, then explicitly checks its validity, identity, and system trust. It does not alter global trust or any other app's connections. Credentialed HTTPS always uses a separate normally verified TLS connection; the inspection trust manager is never used to send credentials. Username/token/password fields are excluded from saved state and autofill, kept only in process memory, and cleared when the scan starts or ends. Permission-flow recreation requires re-entry. Credentials never enter serialized scope, preferences, reports, exports, intents, or NVD queries. Java/Android may temporarily retain immutable copies in memory; the app does not promise complete memory erasure.

## Build and test

Open in Android Studio, or use JDK 17 and an Android SDK:

```bash
./gradlew testDebugUnitTest lintDebug assembleDebug
```

The project uses AGP 8.12.2, Gradle 8.13, compile/target API 36, and minimum API 30. There are no third-party runtime dependencies. Tests use JUnit 4.13.2. GitHub Actions builds an APK, uploads test/lint reports, then runs an Android 16 emulator smoke test against an owned HTTP fixture. The smoke test seeds a v0.2 report, updates to v0.3, verifies retained history, then scans owned HTTP/TLS/Redis/PostgreSQL/SMTP fixtures. It checks TLS probes, untrusted-certificate credential blocking, cleared credential fields, rescan, and PDF/HTML/JSON exports. Repository permissions remain read-only.

For environments with SDK tools installed but Maven access unavailable:

```bash
ANDROID_HOME=/path/to/android-sdk bash tools/build-local.sh
JUNIT_JAR=/path/to/junit-4.13.2.jar HAMCREST_JAR=/path/to/hamcrest-core-1.3.jar bash tools/test-core.sh
```

The SDK-only script requires platform API 36 and build-tools 36.0.0; it compiles resources, Java classes, DEX, aligns and development-signs the APK with debugging disabled. Its key stays in the ignored `app/build` directory. Debug keys from different build environments differ, so switching APK sources may require uninstalling the old build first; export reports before uninstalling.

## Structure

- `app/.../core`: platform-independent configuration, scanning, response parsing, findings, certificate matching, and report rendering.
- `ScanService`: foreground execution, cancellation, network viewpoint, and lifecycle handling.
- `MainActivity`: scan settings, progress, history, evidence review, and document exports.
- `ReportStore`: atomic private report storage.
- `NvdClient`: optional HTTPS lookup, cancellation, response bounds, cache, and rate spacing.
- `PdfExporter`: Android-native paginated PDF export.
- `app/src/test`: local fixtures and security/correctness regression tests; no public targets are contacted.

See [VALIDATION.md](VALIDATION.md) for the shipped build's verification and known limitations.

## Upgrade and report compatibility

The v0.3.0 APK has version code 3 and retains v0.1.0/v0.2.0 report serialization compatibility. Original scanner versions remain attached to old reports. New settings default to off when reading old reports, preserving their original scope. JSON schema 3 adds read-only protocol assignments, TLS-probe settings, and authentication method/port metadata, with no credentials. Rescanning a credentialed report disables authentication until the method and credentials are entered again. Comparison requires identical protocol/TLS settings and excludes credentialed reports because account identity is not stored. Detection-rule changes across scanner versions are recorded as a comparison caveat.
