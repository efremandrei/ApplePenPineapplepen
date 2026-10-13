package info.hen14.applepen.core;

import org.junit.Test;
import static org.junit.Assert.*;
import java.io.ByteArrayInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

public class CoreTest {
    @Test public void validatesLiteralAddressesOnly() {
        assertEquals("192.168.1.10", ScanConfig.validateIp(" 192.168.1.10 "));
        assertEquals("::1", ScanConfig.validateIp("::1"));
        for (String bad : new String[]{"example.com","127.1","012.0.0.1","256.1.1.1","192.168.1.0/24","http://127.0.0.1","::gg","127.0.0.1\r\nHost: attacker"}) assertThrows(IllegalArgumentException.class, () -> ScanConfig.validateIp(bad));
    }
    @Test public void hostnameCannotInjectHttpHeaders() {
        assertEquals("example.com",ScanConfig.validateHostname("EXAMPLE.COM"));
        for (String bad : new String[]{"example.com:443","example.com/path","example.com\r\nX:1","-example.com","example..com"}) assertThrows(IllegalArgumentException.class, () -> ScanConfig.validateHostname(bad));
    }
    @Test public void portsAreValidatedSortedAndDeduplicated() {
        assertEquals(Arrays.asList(22,80,81,82,443),ScanConfig.parsePorts("443,22,80-82,80"));
        assertEquals(65535,ScanConfig.parsePorts("1-65535").size());
        for (String bad : new String[]{"", "0", "65536", "9-1", "80,", "80-90-100", "x", "-1"}) assertThrows(IllegalArgumentException.class, () -> ScanConfig.parsePorts(bad));
    }
    @Test public void ipv6HostHeaderHasBracketsAndNoScope() {
        ScanConfig config = new ScanConfig("::1","","Custom","80",500,1);
        assertEquals("[::1]",config.hostHeader(80,false));
        assertEquals("[::1]:8080",config.hostHeader(8080,false));
        assertEquals("web.example:8443",new ScanConfig("127.0.0.1","web.example","Custom","8443",500,1).hostHeader(8443,true));
    }
    @Test public void wildcardMatchesExactlyOneLabel() {
        assertTrue(CertificateNames.dnsMatches("*.example.com","a.example.com"));
        assertFalse(CertificateNames.dnsMatches("*.example.com","a.b.example.com"));
        assertFalse(CertificateNames.dnsMatches("*.example.com","example.com"));
        assertFalse(CertificateNames.dnsMatches("*.example.com","evil-example.com"));
    }
    private HttpResponse response(String headers, String body) throws Exception {
        String raw = "HTTP/1.1 200 OK\r\nContent-Length: " + body.getBytes(StandardCharsets.UTF_8).length + "\r\n" + headers + "\r\n" + body;
        return HttpResponse.read(new ByteArrayInputStream(raw.getBytes(StandardCharsets.UTF_8)));
    }
    @Test public void headersAreCaseInsensitiveAndCookieValuesRedacted() throws Exception {
        HttpResponse r = response("Content-Type: text/html\r\nsErVeR: Demo\r\nSet-Cookie: session=SUPER_SECRET; Path=/\r\n", "<html>Test</html>");
        assertEquals("Demo",r.header("SERVER"));
        List<ScanReport.Finding> findings = new ArrayList<>(); HttpRules.evaluate(r,443,true,findings);
        assertTrue(findings.stream().anyMatch(f -> f.title.equals("Cookie lacks Secure: session")));
        assertFalse(findings.stream().anyMatch(f -> f.evidence.contains("SUPER_SECRET")));
    }
    @Test public void secureHeadersRemoveApplicableFindings() throws Exception {
        HttpResponse r = response("Content-Type: text/html\r\nContent-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\nX-Content-Type-Options: nosniff\r\nStrict-Transport-Security: max-age=31536000\r\nSet-Cookie: session=x; Secure; HttpOnly\r\n", "<html>OK</html>");
        List<ScanReport.Finding> findings = new ArrayList<>(); HttpRules.evaluate(r,443,true,findings);
        assertTrue(findings.isEmpty());
    }
    @Test public void nonHtmlResponseDoesNotGetHtmlHeaderFindings() throws Exception {
        HttpResponse r = response("Content-Type: application/json\r\n", "{\"ok\":true}");
        List<ScanReport.Finding> findings = new ArrayList<>(); HttpRules.evaluate(r,443,true,findings);
        assertTrue(findings.isEmpty());
    }
    @Test public void malformedHttpIsInconclusiveInsteadOfInventingFindings() {
        assertThrows(java.io.IOException.class, () -> HttpResponse.read(new ByteArrayInputStream("SSH-2.0-demo\r\n".getBytes(StandardCharsets.US_ASCII))));
        assertThrows(java.io.IOException.class, () -> HttpResponse.read(new ByteArrayInputStream("HTTP/1.1 200 OK\r\n".getBytes(StandardCharsets.US_ASCII))));
    }
    @Test public void directoryListingRemainsSuspected() throws Exception {
        HttpResponse r = response("Content-Type: text/html\r\n", "<html><title>Index of /</title></html>");
        List<ScanReport.Finding> findings = new ArrayList<>(); HttpRules.evaluate(r,80,false,findings);
        ScanReport.Finding finding = findings.stream().filter(f -> f.title.equals("Possible directory listing")).findFirst().orElseThrow();
        assertEquals("Suspected",finding.status); assertEquals("Medium",finding.confidence);
    }
    @Test public void exportsEscapeUntrustedServerText() {
        ScanReport report = new ScanReport(new ScanConfig("127.0.0.1","","Custom","80",500,1));
        report.status = "Completed"; report.finishedAt = System.currentTimeMillis();
        report.findings.add(new ScanReport.Finding("<script>alert('x')</script>","Info","High","Observed",80,"\"\n\\\u0000","impact","fix",""));
        assertFalse(ReportExporter.html(report).contains("<script>"));
        assertTrue(ReportExporter.html(report).contains("&lt;script&gt;"));
        assertTrue(ReportExporter.json(report).contains("\\u0000"));
        assertEquals("\"a\\n\\\"b\\\\\"",ReportExporter.quote("a\n\"b\\"));
    }
    @Test public void scannerObservesLocalOpenAndRefusedPorts() throws Exception {
        try (ServerSocket server = new ServerSocket(0)) {
            int closed;
            try (ServerSocket temp = new ServerSocket(0)) { closed = temp.getLocalPort(); }
            ScanConfig config = new ScanConfig("127.0.0.1","","Custom",server.getLocalPort() + "," + closed,300,2);
            ScanReport report = new ScanEngine().run(config,"loopback fixture",(done,total,msg) -> {});
            assertEquals("Completed",report.status); assertEquals(2,report.attempted);
            assertEquals(1,report.ports.size()); assertEquals(server.getLocalPort(),report.ports.get(0).number);
            assertEquals(1,report.closed); assertEquals(0,report.timedOut);
            assertTrue(report.findings.isEmpty());
        }
    }
    @Test public void httpScanPinsConnectionToIpAndUsesOptionalHost() throws Exception {
        ServerSocket fixture = null;
        for (int p : new int[]{8081,8008,8000,8888}) {
            try { fixture = new ServerSocket(p); break; } catch (java.io.IOException ignored) { }
        }
        assertNotNull("Need an available local fixture port",fixture);
        try (ServerSocket server = fixture) {
            server.setSoTimeout(4000); AtomicReference<String> request = new AtomicReference<>();
            Thread responder = new Thread(() -> {
                try {
                    for (int i = 0; i < 2; i++) try (Socket socket = server.accept()) {
                        socket.setSoTimeout(1000);
                        java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(socket.getInputStream(),StandardCharsets.US_ASCII));
                        String first = reader.readLine(); if (first == null) continue;
                        StringBuilder head = new StringBuilder(first);
                        String line; while ((line = reader.readLine()) != null && !line.isEmpty()) head.append('\n').append(line);
                        request.set(head.toString());
                        socket.getOutputStream().write("HTTP/1.1 302 Found\r\nLocation: http://outside-scope.invalid/\r\nContent-Length: 0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
                    }
                } catch (Exception ignored) { }
            }); responder.start();
            ScanReport report = new ScanEngine().run(new ScanConfig("127.0.0.1","site.example","Custom",String.valueOf(server.getLocalPort()),500,1),"fixture",(d,t,m) -> {});
            responder.join(5000);
            assertEquals("Completed",report.status); assertEquals("HTTP",report.ports.get(0).service);
            assertNotNull(request.get()); assertTrue(request.get().contains("Host: site.example:" + server.getLocalPort()));
            assertTrue(report.coverage.stream().anyMatch(line -> line.contains("redirect observed but not followed")));
        }
    }
    @Test public void preCancelledRunIsClearlyPartial() {
        ScanEngine engine = new ScanEngine(); engine.cancel();
        ScanReport r = engine.run(new ScanConfig("127.0.0.1","","Custom","80",300,1),"fixture",(d,t,m) -> {});
        assertEquals("Cancelled",r.status); assertEquals(0,r.attempted);
    }
    @Test public void tlsScanRecordsSelfSignedChainWithoutInventingIdentityMismatch() throws Exception {
        java.nio.file.Path directory = java.nio.file.Files.createTempDirectory("applepen-tls-fixture");
        java.nio.file.Path key = directory.resolve("fixture.p12");
        char[] password = "local-test-only".toCharArray();
        try {
            String keytool = java.nio.file.Path.of(System.getProperty("java.home"),"bin","keytool").toString();
            Process process = new ProcessBuilder(keytool,"-genkeypair","-keystore",key.toString(),"-storetype","PKCS12","-storepass",new String(password),"-alias","fixture","-keyalg","RSA","-keysize","2048","-validity","2","-dname","CN=localhost","-ext","SAN=dns:localhost,ip:127.0.0.1").redirectErrorStream(true).start();
            byte[] log = process.getInputStream().readAllBytes();
            assertEquals(new String(log,StandardCharsets.UTF_8),0,process.waitFor());
            java.security.KeyStore keys = java.security.KeyStore.getInstance("PKCS12");
            try (java.io.InputStream in = java.nio.file.Files.newInputStream(key)) { keys.load(in,password); }
            java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) keys.getCertificate("fixture");
            assertTrue(CertificateNames.matches(cert,"localhost")); assertTrue(CertificateNames.matches(cert,"127.0.0.1")); assertFalse(CertificateNames.matches(cert,"elsewhere.example"));
            javax.net.ssl.KeyManagerFactory managers = javax.net.ssl.KeyManagerFactory.getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm()); managers.init(keys,password);
            javax.net.ssl.SSLContext context = javax.net.ssl.SSLContext.getInstance("TLS"); context.init(managers.getKeyManagers(),null,null);
            javax.net.ssl.SSLServerSocket fixture = null;
            for (int p : new int[]{8443,2376,5986}) try { fixture = (javax.net.ssl.SSLServerSocket)context.getServerSocketFactory().createServerSocket(p); break; } catch (java.io.IOException ignored) { }
            assertNotNull("Need an available TLS fixture port",fixture);
            try (javax.net.ssl.SSLServerSocket server = fixture) {
                server.setSoTimeout(6000);
                Thread responder = new Thread(() -> {
                    for (int i = 0; i < 3; i++) {
                        try (javax.net.ssl.SSLSocket socket = (javax.net.ssl.SSLSocket)server.accept()) {
                            socket.setSoTimeout(1500); socket.startHandshake();
                            java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(socket.getInputStream(),StandardCharsets.US_ASCII));
                            if (reader.readLine() == null) continue;
                            String line; while ((line = reader.readLine()) != null && !line.isEmpty()) { }
                            socket.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}".getBytes(StandardCharsets.US_ASCII));
                        } catch (Exception ignored) { }
                    }
                }); responder.start();
                ScanReport report = new ScanEngine().run(new ScanConfig("127.0.0.1","localhost","Custom",String.valueOf(server.getLocalPort()),1500,1),"TLS fixture",(d,t,m) -> {});
                responder.join(8000);
                assertEquals("Completed",report.status); assertEquals("HTTPS",report.ports.get(0).service);
                assertTrue(report.ports.get(0).evidence.contains("TLSv1"));
                assertTrue(report.findings.stream().anyMatch(f -> f.title.equals("Certificate chain not trusted by this phone")));
                assertFalse(report.findings.stream().anyMatch(f -> f.title.equals("Certificate identity mismatch")));
                assertFalse(report.coverage.stream().anyMatch(line -> line.contains("TLS check inconclusive")));
            }
        } finally { java.nio.file.Files.deleteIfExists(key); java.nio.file.Files.deleteIfExists(directory); }
    }
}
