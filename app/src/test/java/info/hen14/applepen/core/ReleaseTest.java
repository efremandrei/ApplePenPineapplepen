package info.hen14.applepen.core;

import org.junit.Test;
import static org.junit.Assert.*;
import java.io.ObjectInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

public class ReleaseTest {
    private ScanReport report(String ports) { ScanReport r = new ScanReport(new ScanConfig("127.0.0.1","","Custom",ports,300,1)); r.status="Completed"; r.network="fixture"; return r; }
    private ScanReport.Finding finding(String name) { return new ScanReport.Finding(name,"Low","High","Observed",80,"Evidence","Impact","Fix",""); }
    @Test public void extraProtocolPortsCannotExpandOrConflictWithScope() {
        ScanConfig c = new ScanConfig("127.0.0.1","","Custom","8089,9443",300,1,"8089","9443",false);
        assertTrue(c.http(8089)); assertTrue(c.https(9443)); assertFalse(c.http(9443));
        assertThrows(IllegalArgumentException.class,() -> new ScanConfig("127.0.0.1","","Custom","8089",300,1,"8089","9443",false));
        assertThrows(IllegalArgumentException.class,() -> new ScanConfig("127.0.0.1","","Custom","80,443",300,1,"443","",false));
        assertThrows(IllegalArgumentException.class,() -> new ScanConfig("127.0.0.1","","Custom","8089",300,1,"8089","8089",false));
    }
    @Test public void passiveGreetingRecognizesSshOnAnArbitraryPort() throws Exception {
        ScanReport r = sshScan(false,new AtomicInteger());
        assertEquals("SSH",r.ports.get(0).service);
        assertTrue(r.ports.get(0).evidence.startsWith("SSH-2.0-OpenSSH_9.6p1"));
        assertTrue(r.coverage.stream().anyMatch(x -> x.contains("NVD lookup disabled")));
    }
    @Test public void nvdLookupIsOptInAndReturnsLowConfidenceCandidates() throws Exception {
        AtomicInteger calls = new AtomicInteger(); sshScan(false,calls); assertEquals(0,calls.get());
        ScanReport r = sshScan(true,calls); assertEquals(1,calls.get());
        ScanReport.Finding f = r.findings.stream().filter(x -> x.status.equals("Potential CVE")).findFirst().orElseThrow();
        assertEquals("Low",f.confidence); assertEquals(r.ports.get(0).number,f.port);
    }
    @Test public void activeHttpCheckWorksOnAnExplicitNonstandardPort() throws Exception {
        try(ServerSocket server=new ServerSocket(0)) {
            server.setSoTimeout(3000);
            Thread responder=new Thread(() -> { for(int i=0;i<2;i++) try(Socket s=server.accept()) {
                s.setSoTimeout(1000); java.io.BufferedReader reader=new java.io.BufferedReader(new java.io.InputStreamReader(s.getInputStream(),StandardCharsets.US_ASCII));
                if(reader.readLine()==null) continue; String line; while((line=reader.readLine())!=null && !line.isEmpty()) {}
                s.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\n<html></html>".getBytes(StandardCharsets.US_ASCII));
            } catch(Exception ignored) {} }); responder.start();
            String p=String.valueOf(server.getLocalPort());
            ScanReport r=new ScanEngine().run(new ScanConfig("127.0.0.1","","Custom",p,500,1,p,"",false),"fixture",(d,t,m)->{});
            responder.join(4000); assertEquals("HTTP",r.ports.get(0).service); assertTrue(r.findings.stream().anyMatch(f->f.title.contains("Content-Security-Policy")));
        }
    }
    private ScanReport sshScan(boolean enabled,AtomicInteger calls) throws Exception {
        try (ServerSocket server = new ServerSocket(0)) {
            server.setSoTimeout(3000);
            Thread responder = new Thread(() -> { for (int i=0;i<2;i++) try(Socket s=server.accept()) { s.getOutputStream().write("SSH-2.0-OpenSSH_9.6p1\r\n".getBytes(StandardCharsets.US_ASCII)); } catch(Exception ignored) {} }); responder.start();
            CveLookup lookup = new CveLookup() {
                public Result lookup(ProductFingerprint p,int port) { calls.incrementAndGet(); assertEquals("OpenSSH 9.6p1",p.query()); Result r = new Result(); r.findings.add(new ScanReport.Finding("Potential CVE · synthetic fixture","High","Low","Potential CVE",port,"NVD fixture","Unverified","Review vendor", "")); return r; }
                public void cancel() { }
            };
            ScanReport r = new ScanEngine(lookup).run(new ScanConfig("127.0.0.1","","Custom",String.valueOf(server.getLocalPort()),500,1,"","",enabled),"fixture",(d,t,m) -> {});
            responder.join(4000); return r;
        }
    }
    @Test public void fingerprintsRequireVersionBearingProtocolEvidence() {
        assertNull(ProductFingerprint.detect("<html>nginx/1.24.0</html>"));
        assertNull(ProductFingerprint.detect("Server: nginx"));
        assertEquals("1.24.0",ProductFingerprint.detect("HTTP/1.1 200 OK\nServer: nginx/1.24.0").version);
        ProductFingerprint p=ProductFingerprint.detect("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3");
        assertTrue(p.matchesCpe("cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*"));
        assertFalse(p.matchesCpe("cpe:2.3:a:openbsd:openssh:9.6:p2:*:*:*:*:*:*"));
        assertFalse(p.matchesCpe("cpe:2.3:a:evil:openssh:9.6:p1:*:*:*:*:*:*"));
    }
    @Test public void nvdDictionaryRequiresExactVersionAndRejectsDeprecatedProducts() {
        ProductFingerprint p=ProductFingerprint.detect("Server: nginx/1.24.0");
        String right="cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*";
        String wrong="cpe:2.3:a:nginx:nginx:1.25.0:*:*:*:*:*:*:*";
        String json="{\"totalResults\":2,\"products\":[{\"cpe\":{\"deprecated\":false,\"cpeName\":"+ReportExporter.quote(wrong)+"}},{\"cpe\":{\"deprecated\":false,\"cpeName\":"+ReportExporter.quote(right)+"}}]}";
        assertEquals(right,NvdData.selectCpe(json,p));
        assertEquals("",NvdData.selectCpe(json.replace("\"deprecated\":false","\"deprecated\":true"),p));
        assertThrows(IllegalArgumentException.class,() -> NvdData.selectCpe("{}",p));
    }
    @Test public void nvdRecordsRemainPotentialAndPreserveSourceSeverity() {
        ProductFingerprint p=ProductFingerprint.detect("Server: nginx/1.24.0");
        String json="{\"totalResults\":2,\"vulnerabilities\":[{\"cve\":{\"id\":\"CVE-2099-90000001\",\"vulnStatus\":\"Analyzed\",\"descriptions\":[{\"lang\":\"en\",\"value\":\"Synthetic fixture\"}],\"metrics\":{\"cvssMetricV31\":[{\"type\":\"Primary\",\"cvssData\":{\"baseScore\":9.8,\"baseSeverity\":\"CRITICAL\"}}]}}},{\"cve\":{\"id\":\"CVE-2099-90000002\",\"vulnStatus\":\"Rejected\"}}]}";
        CveLookup.Result r=NvdData.findings(json,p,"cpe fixture",8089,"Source timestamp fixture");
        assertEquals(1,r.findings.size()); assertEquals("Critical",r.findings.get(0).severity);
        assertEquals("Low",r.findings.get(0).confidence); assertEquals("Potential CVE",r.findings.get(0).status);
        assertTrue(r.findings.get(0).impact.contains("backports")); assertTrue(r.findings.get(0).evidence.contains("Source timestamp"));
        assertThrows(IllegalArgumentException.class,() -> NvdData.findings("[]",p,"x",8089,"fixture"));
    }
    @Test public void jsonReaderHandlesEscapesNestedDataAndRejectsMalformedInput() {
        Map<String,Object> root=JsonReader.object(JsonReader.parse("{\"a\":[true,false,null,1.25],\"b\":\"x\\n\\u05d0\"}"));
        assertEquals("x\nא",root.get("b")); assertEquals(4,JsonReader.array(root.get("a")).size());
        for(String bad:new String[]{"{\"a\":1,\"a\":2}","[1,]","{\"x\":01}","{\"x\":NaN}","\"bad\\q\"","{\"x\":1} garbage"}) assertThrows(IllegalArgumentException.class,() -> JsonReader.parse(bad));
        assertThrows(IllegalArgumentException.class,() -> JsonReader.parse("[".repeat(66)+"0"+"]".repeat(66)));
    }
    @Test public void comparisonSeparatesMissingFindingsFromAConfirmedFix() {
        ScanReport before=report("80,443"),after=report("80,443");
        before.findings.add(finding("Old")); after.findings.add(finding("New")); before.ports.add(new ScanReport.Port(80));
        after.timeoutPorts.add(80); after.timedOut=1;
        ReportDiff d=ReportDiff.compare(before,after);
        assertEquals(1,d.newFindings); assertEquals(1,d.missingFindings);
        assertTrue(d.changes.stream().anyMatch(x -> x.contains("current result inconclusive")));
        assertFalse(d.changes.stream().anyMatch(x -> x.toLowerCase().contains("fixed")));
        after.timeoutPorts.clear(); after.refusedPorts.add(80);
        assertTrue(ReportDiff.compare(before,after).changes.stream().anyMatch(x -> x.contains("now connection refused")));
    }
    @Test public void comparisonRejectsIncompleteOrDifferentScopesAndViewpoints() {
        ScanReport before=report("80"),after=report("80"); after.status="Cancelled";
        assertThrows(IllegalArgumentException.class,() -> ReportDiff.compare(before,after));
        after.status="Completed"; after.network="VPN";
        assertThrows(IllegalArgumentException.class,() -> ReportDiff.compare(before,after));
        assertThrows(IllegalArgumentException.class,() -> ReportDiff.compare(before,report("443")));
    }
    @Test public void comparisonExportsRoundTripAsValidJson() {
        ScanReport before=report("80"),after=report("80"); after.findings.add(finding("<New>")); after.comparison=ReportDiff.compare(before,after);
        Map<String,Object> json=JsonReader.object(JsonReader.parse(ReportExporter.json(after)));
        assertEquals(2,JsonReader.integer(json.get("schemaVersion")));
        assertEquals(1,JsonReader.integer(JsonReader.object(json.get("comparison")).get("newFindings")));
        assertTrue(ReportExporter.html(after).contains("&lt;New&gt;")); assertTrue(ReportExporter.text(after).contains("COMPARISON"));
    }
    @Test public void legacyReportsDeserializeAndKeepTheirOriginalScannerVersion() throws Exception {
        try(ObjectInputStream in=new ObjectInputStream(getClass().getResourceAsStream("/legacy-v010.report"))) {
            ScanReport legacy=(ScanReport)in.readObject(); assertEquals("0.1.0",legacy.version());
            assertNull(legacy.config.extraHttpPorts); assertTrue(legacy.config.http(80)); assertFalse(legacy.config.lookupCves);
            assertTrue(ReportExporter.json(legacy).contains("ApplePen 0.1.0"));
            ScanReport current=report("80,443"); current.refusedPorts.add(80);
            assertTrue(ReportDiff.compare(legacy,current).caveats.stream().anyMatch(x -> x.contains("Scanner version changed")));
        }
    }
}
