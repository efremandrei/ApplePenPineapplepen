package info.hen14.applepen.core;

import java.io.ByteArrayOutputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Comparator;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public final class ScanEngine {
    public interface Progress { void update(int completed, int total, String text); }
    private final AtomicBoolean stopped = new AtomicBoolean();
    private final Set<Socket> sockets = ConcurrentHashMap.newKeySet();
    private final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor();
    private volatile boolean budgetExpired;
    private final CveLookup cveLookup;
    public ScanEngine() { this(null); }
    public ScanEngine(CveLookup cveLookup) { this.cveLookup = cveLookup; }
    public void cancel() { stopped.set(true); for (Socket socket : sockets) close(socket); if (cveLookup != null) cveLookup.cancel(); }
    private void close(Socket socket) { try { socket.close(); } catch (Exception ignored) { } sockets.remove(socket); }
    private Socket connect(ScanConfig config, int port) throws Exception {
        if (stopped.get()) throw new InterruptedException("Scan stopped");
        Socket socket = new Socket();
        sockets.add(socket);
        timer.schedule(() -> close(socket), Math.min(8000, Math.max(3000, config.timeoutMs * 2)), TimeUnit.MILLISECONDS);
        try {
            socket.connect(new InetSocketAddress(InetAddress.getByName(config.ip), port), config.timeoutMs);
            socket.setSoTimeout(config.timeoutMs);
            if (stopped.get()) throw new InterruptedException("Scan stopped");
            return socket;
        } catch (Exception e) { close(socket); throw e; }
    }
    private static final class Attempt {
        final int port, state;
        final String detail;
        Attempt(int port, int state, String detail) { this.port = port; this.state = state; this.detail = detail; }
    }
    private Attempt attempt(ScanConfig config, int port) {
        try { Socket socket = connect(config, port); close(socket); return new Attempt(port, 0, ""); }
        catch (SocketTimeoutException e) { return new Attempt(port, 2, "Timed out"); }
        catch (ConnectException e) { return new Attempt(port, e.getMessage() != null && e.getMessage().toLowerCase(java.util.Locale.ROOT).contains("refused") ? 1 : 3, String.valueOf(e.getMessage())); }
        catch (Exception e) { return new Attempt(port, 3, e.getClass().getSimpleName() + ": " + e.getMessage()); }
    }
    public ScanReport run(ScanConfig config, String network, Progress progress) {
        ScanReport report = new ScanReport(config);
        report.network = network;
        return run(report, progress);
    }
    public ScanReport run(ScanReport report, Progress progress) {
        ScanConfig config = report.config;
        report.coverage.add("One literal IP; TCP connections only. No UDP scan, raw packets, credential guessing, exploit execution, or authenticated application tests.");
        report.coverage.add("Root HTTP response only, up to 16 KiB headers and 8 KiB body. Redirects, links and external resources are not followed. Cookie values are redacted.");
        report.coverage.add(config.lookupCves ? "Optional NVD lookup enabled: product/version and dictionary CPE names are sent to NVD, never the target IP or hostname. CVEs are unverified candidates; vendor patch status and exploitability are not tested." : "NVD lookup disabled. No product/version queries are sent to NVD; CVE applicability and patch verification are not performed.");
        if (config.hostname.isEmpty()) report.coverage.add("No hostname supplied: web checks describe the IP's default site; certificate identity is checked against the IP SAN, not an inferred hostname.");
        report.coverage.add("Timeouts and network errors are inconclusive, not evidence of a closed port. A completed scan does not establish that the system is secure.");
        ExecutorService pool = Executors.newFixedThreadPool(config.concurrency);
        ExecutorCompletionService<Attempt> completion = new ExecutorCompletionService<>(pool);
        timer.schedule(() -> { budgetExpired = true; cancel(); }, config.budgetMs, TimeUnit.MILLISECONDS);
        int submitted = 0, received = 0;
        try {
            while (submitted < Math.min(config.ports.size(), config.concurrency * 2)) {
                final int port = config.ports.get(submitted++);
                completion.submit(() -> attempt(config, port));
            }
            long lastProgress = 0;
            while (received < config.ports.size() && !stopped.get()) {
                Future<Attempt> next = completion.poll(200, TimeUnit.MILLISECONDS);
                if (next == null) continue;
                Attempt a = next.get(); received++; report.attempted++;
                if (a.state == 0) report.ports.add(new ScanReport.Port(a.port));
                else if (a.state == 1) { report.closed++; report.refusedPorts.add(a.port); }
                else if (a.state == 2) { report.timedOut++; report.timeoutPorts.add(a.port); }
                else { report.failed++; report.errorPorts.add(a.port); if (report.failed == 1) report.coverage.add("First connection error: " + HttpRules.clean(a.detail)); }
                if (submitted < config.ports.size()) {
                    final int port = config.ports.get(submitted++);
                    completion.submit(() -> attempt(config, port));
                }
                if (System.currentTimeMillis() - lastProgress > 200 || received == config.ports.size()) {
                    progress.update(received, config.ports.size(), "Scanning TCP ports · " + report.ports.size() + " open");
                    lastProgress = System.currentTimeMillis();
                }
            }
            report.ports.sort(Comparator.comparingInt(p -> p.number));
            java.util.ArrayList<ScanReport.Port> inspectionOrder = new java.util.ArrayList<>(report.ports);
            inspectionOrder.sort(Comparator.comparingInt((ScanReport.Port p) -> config.http(p.number) || config.tls(p.number) ? 0 : p.number == 22 || p.number == 21 ? 1 : 2).thenComparingInt(p -> p.number));
            int inspected = 0;
            for (ScanReport.Port port : inspectionOrder) {
                if (stopped.get()) break;
                if (inspected >= 64) { report.coverage.add("Service inspection capped at 64 open ports; remaining open ports have connection observations only."); break; }
                progress.update(report.attempted, config.ports.size(), "Inspecting TCP " + port.number + " · " + (++inspected) + "/" + Math.min(64, report.ports.size()));
                inspect(config, port, report);
            }
            if (config.lookupCves && !stopped.get()) lookupCves(report, progress);
            if (stopped.get()) report.status = budgetExpired ? "Partial · time limit" : "Cancelled";
            else report.status = report.attempted > 0 && report.ports.isEmpty() && report.closed == 0 ? "Inconclusive · no TCP response" : "Completed";
        } catch (Exception e) {
            report.status = stopped.get() ? (budgetExpired ? "Partial · time limit" : "Cancelled") : "Failed";
            if (!stopped.get()) report.error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            cancel(); pool.shutdownNow(); timer.shutdownNow();
            report.finishedAt = System.currentTimeMillis();
            report.coverage.add("Processed " + report.attempted + " of " + config.ports.size() + " selected ports. Service observations are best effort and subject to phone TLS capabilities.");
            report.findings.sort(Comparator.comparingInt(f -> severityOrder(f.severity)));
        }
        return report;
    }
    public static int severityOrder(String severity) { return switch (severity) { case "Critical" -> 0; case "High" -> 1; case "Medium" -> 2; case "Low" -> 3; default -> 4; }; }
    private void inspect(ScanConfig config, ScanReport.Port port, ScanReport report) {
        int p = port.number;
        if (config.http(p)) { http(config, port, report, false); return; }
        if (config.tls(p)) {
            tls(config, port, report);
            if (!stopped.get() && config.https(p)) http(config, port, report, true);
            return;
        }
        // Receive-only greeting detection on any remaining port; never send arbitrary payloads.
        banner(config, port, report);
    }
    private void banner(ScanConfig config, ScanReport.Port port, ScanReport report) {
        Socket socket = null;
        try {
            socket = connect(config, port.number);
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            while (bytes.size() < 1024) {
                int value = socket.getInputStream().read();
                if (value == -1 || value == '\n') break;
                bytes.write(value);
            }
            String line = HttpRules.clean(new String(bytes.toByteArray(), StandardCharsets.UTF_8).trim());
            if (line.startsWith("SSH-")) {
                port.service = "SSH"; port.evidence = line;
                if (line.startsWith("SSH-1.5-")) report.findings.add(new ScanReport.Finding("Legacy SSH protocol advertised", "High", "High", "Observed", port.number, line, "SSH protocol 1 is obsolete and lacks modern protections.", "Disable SSH protocol 1 and update the server.", "https://www.openssh.com/legacy.html"));
            } else if (line.startsWith("220") && line.toLowerCase(java.util.Locale.ROOT).contains("ftp")) {
                port.service = "FTP banner"; port.evidence = line;
                report.findings.add(new ScanReport.Finding("FTP service exposed", "Low", "High", "Observed", port.number, line, "Plain FTP credentials and data are unencrypted unless TLS is negotiated. TLS support and login behavior were not tested.", "Prefer SFTP or require FTPS; restrict access to intended clients.", "https://www.rfc-editor.org/rfc/rfc4217"));
            } else if (line.startsWith("220") && line.toUpperCase(java.util.Locale.ROOT).contains("SMTP")) { port.service = "SMTP greeting"; port.evidence = line;
            } else if (line.startsWith("+OK") && line.toUpperCase(java.util.Locale.ROOT).contains("POP")) { port.service = "POP greeting"; port.evidence = line;
            } else if (line.startsWith("* OK") && line.toUpperCase(java.util.Locale.ROOT).contains("IMAP")) { port.service = "IMAP greeting"; port.evidence = line;
            } else if (port.number == 23 && !line.isEmpty()) {
                port.service = "Possible Telnet"; port.evidence = line;
                report.findings.add(new ScanReport.Finding("Possible Telnet service", "Medium", "Medium", "Suspected", port.number, line, "If this is Telnet, sessions may expose credentials and commands in plaintext.", "Confirm the protocol, replace Telnet with SSH, and restrict access.", ""));
            } else if (!line.isEmpty()) { port.service = "Banner observed"; port.evidence = line; }
            else report.coverage.add("TCP " + port.number + ": no server-first greeting received. Assign an HTTP/HTTPS port explicitly if appropriate.");
        } catch (Exception e) { if (!stopped.get()) report.coverage.add("TCP " + port.number + ": banner check inconclusive (" + e.getClass().getSimpleName() + ")."); }
        finally { if (socket != null) close(socket); }
    }
    private SSLSocket secure(ScanConfig config, int port, String protocol, CaptureTrust trust) throws Exception {
        Socket raw = connect(config, port);
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[]{trust}, new SecureRandom());
            SSLSocket ssl = (SSLSocket) context.getSocketFactory().createSocket(raw, config.identity(), port, true);
            sockets.add(ssl);
            ssl.setSoTimeout(config.timeoutMs);
            SSLParameters parameters = ssl.getSSLParameters();
            if (!config.hostname.isEmpty()) parameters.setServerNames(Collections.singletonList(new SNIHostName(config.hostname)));
            if (config.https(port)) parameters.setApplicationProtocols(new String[]{"http/1.1"});
            ssl.setSSLParameters(parameters);
            if (protocol != null) ssl.setEnabledProtocols(new String[]{protocol});
            ssl.startHandshake();
            return ssl;
        } catch (Exception e) { close(raw); throw e; }
    }
    /** Inspection only. No global trust settings or normal application connections are modified. */
    private static final class CaptureTrust implements X509TrustManager {
        X509Certificate[] chain;
        public void checkClientTrusted(X509Certificate[] certificates, String authType) { }
        public void checkServerTrusted(X509Certificate[] certificates, String authType) { chain = certificates; }
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }
    private void tls(ScanConfig config, ScanReport.Port port, ScanReport report) {
        SSLSocket socket = null;
        try {
            CaptureTrust captured = new CaptureTrust();
            socket = secure(config, port.number, null, captured);
            port.service = "TLS service";
            String negotiated = socket.getSession().getProtocol() + " / " + socket.getSession().getCipherSuite();
            X509Certificate cert = captured.chain[0];
            port.evidence = negotiated + "\nSubject: " + cert.getSubjectX500Principal().getName() + "\nValid until: " + cert.getNotAfter();
            try { cert.checkValidity(); } catch (Exception e) { tlsFinding(report, port, "Certificate outside its validity period", "Medium", "Observed", e.getClass().getSimpleName() + "; " + port.evidence, "Clients may reject this certificate.", "Renew the certificate and verify its validity dates."); }
            if (!CertificateNames.matches(cert, config.identity())) tlsFinding(report, port, "Certificate identity mismatch", "Medium", "Observed", "Requested identity: " + config.identity() + "; no matching subject alternative name.", "Standard clients may reject the requested identity. An IP-only scan may be observing a default virtual host.", "Supply the intended hostname; if it still fails, deploy a certificate with the correct SAN.");
            try {
                TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                factory.init((java.security.KeyStore) null);
                X509TrustManager system = null;
                for (TrustManager manager : factory.getTrustManagers()) if (manager instanceof X509TrustManager) system = (X509TrustManager) manager;
                if (system == null) throw new IllegalStateException("No system trust manager");
                system.checkServerTrusted(captured.chain, cert.getPublicKey().getAlgorithm());
            } catch (Exception e) { tlsFinding(report, port, "Certificate chain not trusted by this phone", "Medium", "Observed", e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage()), "The presented chain did not pass this phone's trust check. Private PKI or incomplete chains may explain this finding.", "Review the chain and intended trust store; deploy intermediates or the appropriate private CA."); }
            if (negotiated.startsWith("TLSv1 ") || negotiated.startsWith("TLSv1.1 ")) tlsFinding(report, port, "Obsolete TLS protocol negotiated", "High", "Observed", negotiated, "The endpoint accepts an obsolete TLS protocol.", "Require TLS 1.2 or newer.");
            report.coverage.add("TCP " + port.number + ": observed one negotiated TLS protocol/cipher; exhaustive cipher and legacy protocol enumeration was not performed.");
        } catch (Exception e) { if (!stopped.get()) report.coverage.add("TCP " + port.number + ": TLS check inconclusive (" + e.getClass().getSimpleName() + "). Phone protocol support, client authentication, or server behavior may explain failure."); }
        finally { if (socket != null) close(socket); }
    }
    private void tlsFinding(ScanReport report, ScanReport.Port port, String title, String severity, String status, String evidence, String impact, String fix) {
        report.findings.add(new ScanReport.Finding(title, severity, "High", status, port.number, HttpRules.clean(evidence), impact, fix, "https://owasp.org/www-project-web-security-testing-guide/"));
    }
    private void http(ScanConfig config, ScanReport.Port port, ScanReport report, boolean tls) {
        Socket socket = null;
        try {
            socket = tls ? secure(config, port.number, null, new CaptureTrust()) : connect(config, port.number);
            String request = "GET / HTTP/1.1\r\nHost: " + config.hostHeader(port.number, tls) + "\r\nUser-Agent: ApplePen/" + AppVersion.VERSION + "\r\nAccept: text/html,*/*;q=0.1\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n";
            socket.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();
            HttpResponse response = HttpResponse.read(socket.getInputStream());
            port.service = tls ? "HTTPS" : "HTTP";
            port.evidence += "\n" + HttpRules.clean(response.statusLine);
            if (!response.header("server").isEmpty()) port.evidence += "\nServer: " + HttpRules.clean(response.header("server"));
            HttpRules.evaluate(response, port.number, tls, report.findings);
            if (response.code >= 300 && response.code < 400) report.coverage.add("TCP " + port.number + ": redirect observed but not followed; destination and subsequent pages were not tested.");
            if (response.truncated) report.coverage.add("TCP " + port.number + ": root body truncated, encoded, or chunked; content checks are limited.");
        } catch (Exception e) { if (!stopped.get()) report.coverage.add("TCP " + port.number + ": HTTP root check inconclusive (" + e.getClass().getSimpleName() + ")."); }
        finally { if (socket != null) close(socket); }
    }
    private void lookupCves(ScanReport report, Progress progress) {
        if (cveLookup == null) { report.coverage.add("NVD lookup was requested but no lookup client is available."); return; }
        java.util.Map<String, java.util.ArrayList<ScanReport.Port>> groups = new java.util.LinkedHashMap<>();
        for (ScanReport.Port p : report.ports) { ProductFingerprint product = ProductFingerprint.detect(p.evidence); if (product != null) groups.computeIfAbsent(product.query(),key -> new java.util.ArrayList<>()).add(p); }
        if (groups.isEmpty()) report.coverage.add("No supported version-bearing OpenSSH, nginx, Apache HTTP Server, or vsftpd banner was found. No NVD queries were sent.");
        int products = 0;
        for (java.util.ArrayList<ScanReport.Port> ports : groups.values()) {
            if (stopped.get()) break;
            if (products++ >= 3) { report.coverage.add("NVD lookup capped at 3 distinct product/version pairs per scan; additional products were not queried."); break; }
            ProductFingerprint product = ProductFingerprint.detect(ports.get(0).evidence);
            progress.update(report.attempted,report.config.ports.size(),"NVD candidate lookup · " + product.query());
            try {
                CveLookup.Result result = cveLookup.lookup(product,ports.get(0).number); report.coverage.addAll(result.coverage);
                for (ScanReport.Port port : ports) for (ScanReport.Finding f : result.findings) report.findings.add(new ScanReport.Finding(f.title,f.severity,f.confidence,f.status,port.number,f.evidence,f.impact,f.remediation,f.reference));
            } catch (Exception e) { if (!stopped.get()) report.coverage.add("NVD lookup unavailable for " + product.query() + ": " + HttpRules.clean(String.valueOf(e.getMessage())) + ". No CVE conclusion can be drawn."); }
        }
    }
}
