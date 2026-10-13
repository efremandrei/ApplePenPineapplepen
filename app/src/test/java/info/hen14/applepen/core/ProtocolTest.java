package info.hen14.applepen.core;

import org.junit.BeforeClass;
import org.junit.AfterClass;
import org.junit.Test;
import static org.junit.Assert.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyStore;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.net.ssl.*;

public class ProtocolTest {
    private static SSLContext serverContext, trustedClient, originalDefault;
    private static Path directory, key;
    @BeforeClass public static void certificates() throws Exception {
        originalDefault = SSLContext.getDefault(); directory = Files.createTempDirectory("applepen-v3-test"); key = directory.resolve("fixture.p12");
        Process p = new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin","keytool").toString(),"-genkeypair","-keystore",key.toString(),"-storetype","PKCS12","-storepass","local-test-only","-alias","fixture","-keyalg","RSA","-keysize","2048","-validity","2","-dname","CN=localhost","-ext","SAN=dns:localhost,ip:127.0.0.1").redirectErrorStream(true).start();
        byte[] log = p.getInputStream().readAllBytes(); assertEquals(new String(log,StandardCharsets.UTF_8),0,p.waitFor());
        KeyStore keys = KeyStore.getInstance("PKCS12"); try(InputStream in=Files.newInputStream(key)) { keys.load(in,"local-test-only".toCharArray()); }
        KeyManagerFactory km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()); km.init(keys,"local-test-only".toCharArray());
        serverContext=SSLContext.getInstance("TLS"); serverContext.init(km.getKeyManagers(),null,null);
        KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType()); trust.load(null,null); trust.setCertificateEntry("fixture",keys.getCertificate("fixture"));
        TrustManagerFactory tm = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); tm.init(trust);
        trustedClient=SSLContext.getInstance("TLS"); trustedClient.init(null,tm.getTrustManagers(),null);
    }
    @AfterClass public static void cleanup() throws Exception { SSLContext.setDefault(originalDefault); Files.deleteIfExists(key); Files.deleteIfExists(directory); }
    private ScanConfig config(int port,String hostname,String type,boolean enumerate,String auth) {
        String p=String.valueOf(port);
        return new ScanConfig("127.0.0.1",hostname,"Custom",p,1000,1,"",type.equals("HTTPS") ? p : "",false,true,type.equals("Redis") ? p : "",type.equals("Postgres") ? p : "",enumerate,auth,auth.equals("None") ? 0 : port);
    }
    private ScanReport scan(ScanConfig c) { return new ScanEngine().run(c,"owned fixture",(d,t,m)->{}); }
    private InputStream bytes(String value) { return new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8)); }
    @Test public void respAndSmtpParsersRejectIncompleteOversizedAndAmbiguousReplies() throws Exception {
        assertEquals("+PONG",ProtocolIO.redis(bytes("+PONG\r\n")));
        assertEquals("$abc",ProtocolIO.redis(bytes("$3\r\nabc\r\n")));
        for(String s:new String[]{"$99999\r\n","$3\r\na","+PONG\n","*2\r\n","$-1\r\n"}) assertThrows(IOException.class,()->ProtocolIO.redis(bytes(s)));
        assertEquals(2,ProtocolIO.smtp(bytes("250-demo\r\n250 STARTTLS\r\n"),250).size());
        for(String s:new String[]{"250-demo\r\n","250-demo\r\n220 OK\r\n","250 OK\n","250xOK\r\n"}) assertThrows(IOException.class,()->ProtocolIO.smtp(bytes(s),250));
    }
    @Test public void protocolAssignmentsStayWithinScopeAndCannotConflict() {
        ScanConfig c=config(16379,"","Redis",false,"None"); assertTrue(c.redis(16379)); assertTrue(c.redis(6379)); assertFalse(c.redis(80));
        assertThrows(IllegalArgumentException.class,()->new ScanConfig("127.0.0.1","","Custom","6379",500,1,"6379","",false,true,"","",false,"None",0));
        assertThrows(IllegalArgumentException.class,()->new ScanConfig("127.0.0.1","","Custom","443",500,1,"","",false,true,"16379","",false,"None",0));
        assertThrows(IllegalArgumentException.class,()->new ScanConfig("127.0.0.1","","Custom","80",500,1,"","",false,true,"","",false,"Bearer",80));
        assertFalse(new ScanConfig("127.0.0.1","","Custom","6379",500,1).redis(6379));
    }
    interface Handler { void handle(Socket socket) throws Exception; }
    static final class Fixture implements AutoCloseable {
        final ServerSocket server; final Thread thread; final List<Throwable> failures=new CopyOnWriteArrayList<>(); volatile boolean running=true;
        Fixture(ServerSocket server,Handler handler) throws Exception {
            this.server=server; server.setSoTimeout(250);
            thread=new Thread(()->{ while(running) try(Socket socket=server.accept()) { socket.setSoTimeout(1800); handler.handle(socket); } catch(SocketTimeoutException ignored) {} catch(Throwable e) { if(running && !(e instanceof SSLException) && !(e instanceof EOFException) && !(e instanceof SocketException)) failures.add(e); } }); thread.start();
        }
        int port() { return server.getLocalPort(); }
        public void close() throws Exception { running=false; server.close(); thread.join(3000); assertFalse("Fixture thread did not stop",thread.isAlive()); assertTrue("Fixture failed: " + failures,failures.isEmpty()); }
    }
    @Test public void redisOnlySendsPingAndInfoServerAndNeverReportsOtherInfoFields() throws Exception {
        List<String> commands=new CopyOnWriteArrayList<>();
        try(Fixture f=new Fixture(new ServerSocket(0),s->{
            if(s.getInputStream().read() < 0) return;
            String rest=ProtocolIO.line(s.getInputStream(),100); assertEquals("1",rest); assertEquals("$4",ProtocolIO.line(s.getInputStream(),100)); commands.add(ProtocolIO.line(s.getInputStream(),100));
            s.getOutputStream().write("+PONG\r\n".getBytes(StandardCharsets.US_ASCII));
            assertEquals("*2",ProtocolIO.line(s.getInputStream(),100)); assertEquals("$4",ProtocolIO.line(s.getInputStream(),100)); commands.add(ProtocolIO.line(s.getInputStream(),100)); assertEquals("$6",ProtocolIO.line(s.getInputStream(),100)); commands.add(ProtocolIO.line(s.getInputStream(),100));
            String body="# Server\r\nredis_version:7.4.1\r\nconfig_file:PRIVATE_PATH\r\n";
            s.getOutputStream().write(("$" + body.length() + "\r\n" + body + "\r\n").getBytes(StandardCharsets.US_ASCII));
        })) {
            ScanReport r=scan(config(f.port(),"","Redis",false,"None")); assertEquals("Redis-compatible",r.ports.get(0).service);
            assertTrue(r.findings.stream().anyMatch(x->x.title.startsWith("Redis server information"))); assertFalse(ReportExporter.json(r).contains("PRIVATE_PATH"));
            assertEquals(List.of("PING","INFO","server"),commands);
        }
    }
    @Test public void redisNoauthIsAnObservationWithoutInventingUnauthenticatedAccess() throws Exception {
        try(Fixture f=new Fixture(new ServerSocket(0),s->{ if(s.getInputStream().read()<0) return; for(int i=0;i<3;i++) ProtocolIO.line(s.getInputStream(),100); s.getOutputStream().write("-NOAUTH Authentication required.\r\n".getBytes(StandardCharsets.US_ASCII)); })) {
            ScanReport r=scan(config(f.port(),"","Redis",false,"None")); assertEquals("Redis-compatible",r.ports.get(0).service); assertTrue(r.findings.isEmpty()); assertTrue(r.ports.get(0).evidence.contains("restriction"));
        }
    }
    private Fixture postgres(boolean tls) throws Exception {
        return new Fixture(new ServerSocket(0),s->{ byte[] request=s.getInputStream().readNBytes(8); if(request.length==0) return; assertArrayEquals(new byte[]{0,0,0,8,4,(byte)210,22,47},request); s.getOutputStream().write(tls ? 'S' : 'N'); s.getOutputStream().flush();
            if(tls) try(SSLSocket secure=(SSLSocket)serverContext.getSocketFactory().createSocket(s,"localhost",s.getPort(),true)) { secure.setUseClientMode(false); secure.setSoTimeout(1800); secure.startHandshake(); assertEquals(-1,secure.getInputStream().read()); }
            else assertEquals(-1,s.getInputStream().read());
        });
    }
    @Test public void postgresSslRequestDeclineDoesNotAttemptADatabaseLogin() throws Exception {
        try(Fixture f=postgres(false)) { ScanReport r=scan(config(f.port(),"","Postgres",false,"None")); assertEquals("PostgreSQL-compatible",r.ports.get(0).service); assertTrue(r.findings.stream().anyMatch(x->x.title.contains("declined TLS"))); }
    }
    @Test public void postgresTlsNegotiationInspectsCertificatesWithoutStartupOrQueries() throws Exception {
        try(Fixture f=postgres(true)) { ScanReport r=scan(config(f.port(),"localhost","Postgres",false,"None")); assertTrue(r.ports.get(0).evidence.contains("SSLRequest returned S")); assertTrue(r.ports.get(0).evidence.contains("TLSv1")); assertFalse(r.coverage.stream().anyMatch(x->x.contains("PostgreSQL SSLRequest/TLS inspection inconclusive"))); }
    }
    private Fixture smtp(boolean tls,List<String> commands) throws Exception {
        return new Fixture(new ServerSocket(0),s->{ s.getOutputStream().write("220 fixture ESMTP\r\n".getBytes(StandardCharsets.US_ASCII)); s.getOutputStream().flush();
            BufferedReader reader=new BufferedReader(new InputStreamReader(s.getInputStream(),StandardCharsets.US_ASCII)); String line=reader.readLine(); if(line==null) return; commands.add(line); assertEquals("EHLO applepen.invalid",line);
            s.getOutputStream().write((tls ? "250-fixture\r\n250 STARTTLS\r\n" : "250 fixture\r\n").getBytes(StandardCharsets.US_ASCII)); s.getOutputStream().flush();
            if(tls) { line=reader.readLine(); commands.add(line); assertEquals("STARTTLS",line); s.getOutputStream().write("220 Ready\r\n".getBytes(StandardCharsets.US_ASCII)); s.getOutputStream().flush();
                try(SSLSocket secure=(SSLSocket)serverContext.getSocketFactory().createSocket(s,"localhost",s.getPort(),true)) { secure.setUseClientMode(false); secure.setSoTimeout(1800); secure.startHandshake(); assertEquals(-1,secure.getInputStream().read()); }
            } else assertNull(reader.readLine());
        });
    }
    @Test public void smtpWithoutStarttlsIsInformationalAndDoesNotSendEmailCommands() throws Exception {
        List<String> commands=new CopyOnWriteArrayList<>(); try(Fixture f=smtp(false,commands)) { ScanReport r=scan(config(f.port(),"","SMTP",false,"None")); assertEquals("SMTP-compatible",r.ports.get(0).service); assertEquals(List.of("EHLO applepen.invalid"),commands); assertEquals("Info",r.findings.get(0).severity); }
    }
    @Test public void smtpStarttlsInspectsTheCertificateAndSendsNoAuthOrMail() throws Exception {
        List<String> commands=new CopyOnWriteArrayList<>(); try(Fixture f=smtp(true,commands)) { ScanReport r=scan(config(f.port(),"localhost","SMTP",false,"None")); assertTrue(r.ports.get(0).evidence.contains("TLSv1")); assertEquals(List.of("EHLO applepen.invalid","STARTTLS"),commands); }
    }
    @Test public void credentialsRejectHeaderInjectionAreNotSerializableAndCanBeCleared() {
        assertFalse(Serializable.class.isAssignableFrom(AuthCredentials.class));
        for(String bad:new String[]{"","x\r\nX:a","x y"}) assertThrows(IllegalArgumentException.class,()->new AuthCredentials("Bearer","",bad));
        assertThrows(IllegalArgumentException.class,()->new AuthCredentials("Basic","x:y","secret"));
        AuthCredentials c=new AuthCredentials("Basic","fixture","password"); assertEquals("Basic Zml4dHVyZTpwYXNzd29yZA==",c.authorization()); c.close(); assertThrows(IllegalStateException.class,c::authorization);
    }
    private Fixture https(List<String> requests, boolean modernOnly) throws Exception {
        SSLServerSocket server=(SSLServerSocket)serverContext.getServerSocketFactory().createServerSocket(0); if(modernOnly) server.setEnabledProtocols(new String[]{"TLSv1.2"});
        return new Fixture(server,s->{ SSLSocket ssl=(SSLSocket)s; ssl.startHandshake(); BufferedReader reader=new BufferedReader(new InputStreamReader(s.getInputStream(),StandardCharsets.UTF_8)); String first=reader.readLine(); if(first==null) return;
            StringBuilder request=new StringBuilder(first); String line; while((line=reader.readLine())!=null && !line.isEmpty()) request.append('\n').append(line); requests.add(request.toString());
            boolean auth=request.toString().contains("Authorization:"); String secret=auth ? "fixture-token" : "public";
            String body="<html>" + secret + "</html>";
            ssl.getOutputStream().write(("HTTP/1.1 200 " + secret + "\r\nContent-Type: text/html\r\nServer: " + secret + "\r\nSet-Cookie: " + secret + "=" + secret + "\r\nLocation: https://outside-scope.invalid/" + secret + "\r\nContent-Length: " + body.length() + "\r\n\r\n" + body).getBytes(StandardCharsets.UTF_8));
        });
    }
    @Test public void trustedCredentialRequestIsPinnedRedactedAndAbsentFromSerializedHistory() throws Exception {
        List<String> requests=new CopyOnWriteArrayList<>(); SSLContext.setDefault(trustedClient);
        try(Fixture f=https(requests,false)) {
            AuthCredentials c=new AuthCredentials("Bearer","","fixture-token"); ScanReport r=new ScanEngine(null,c).run(config(f.port(),"localhost","HTTPS",false,"Bearer"),"fixture",(d,t,m)->{});
            assertEquals(2,requests.size()); assertTrue(requests.get(1).contains("Authorization: Bearer fixture-token")); assertTrue(requests.get(1).contains("Host: localhost:" + f.port()));
            assertTrue(r.findings.stream().anyMatch(x->x.title.equals("Authenticated HTTPS root response")));
            for(String export:List.of(ReportExporter.json(r),ReportExporter.html(r),String.join("\n",ReportExporter.text(r)))) assertFalse(export.contains("fixture-token"));
            ByteArrayOutputStream bytes=new ByteArrayOutputStream(); try(ObjectOutputStream out=new ObjectOutputStream(bytes)) { out.writeObject(r); }
            assertFalse(bytes.toString(StandardCharsets.ISO_8859_1).contains("fixture-token")); assertThrows(IllegalStateException.class,c::authorization);
        } finally { SSLContext.setDefault(originalDefault); }
    }
    @Test public void untrustedCertificateBlocksAuthorizationBeforeAnyCredentialBytes() throws Exception {
        blockedAuth(originalDefault,"localhost");
    }
    @Test public void trustedButMismatchedIdentityAlsoBlocksAuthorization() throws Exception {
        blockedAuth(trustedClient,"wrong.example");
    }
    private void blockedAuth(SSLContext client,String hostname) throws Exception {
        List<String> requests=new CopyOnWriteArrayList<>(); SSLContext.setDefault(client);
        try(Fixture f=https(requests,false)) {
            ScanReport r=new ScanEngine(null,new AuthCredentials("Bearer","","fixture-token")).run(config(f.port(),hostname,"HTTPS",false,"Bearer"),"fixture",(d,t,m)->{});
            assertEquals(1,requests.size()); assertFalse(requests.get(0).contains("Authorization:"));
            assertTrue(r.coverage.stream().anyMatch(x->x.contains("blocked before sending Authorization"))); assertFalse(ReportExporter.json(r).contains("fixture-token"));
        } finally { SSLContext.setDefault(originalDefault); }
    }
    @Test public void missingEphemeralCredentialsAreSkippedInsteadOfReused() throws Exception {
        List<String> requests=new CopyOnWriteArrayList<>(); try(Fixture f=https(requests,false)) { ScanReport r=scan(config(f.port(),"localhost","HTTPS",false,"Basic")); assertEquals(1,requests.size()); assertTrue(r.coverage.stream().anyMatch(x->x.contains("ephemeral credentials were unavailable"))); }
    }
    @Test public void tlsVersionFailuresRemainInconclusiveAndSuccessfulModernHandshakeIsRecorded() throws Exception {
        List<String> requests=new CopyOnWriteArrayList<>(); try(Fixture f=https(requests,true)) { ScanReport r=scan(config(f.port(),"localhost","HTTPS",true,"None")); assertTrue(r.coverage.stream().anyMatch(x->x.contains("TLSv1.2 accepted"))); assertTrue(r.coverage.stream().anyMatch(x->x.contains("TLSv1.3 probe inconclusive"))); assertFalse(r.findings.stream().anyMatch(x->x.title.startsWith("Obsolete TLS"))); }
    }
    @Test public void replacedCredentialCannotBeConsumedByAnEarlierStart() {
        try(AuthHandoff h=new AuthHandoff()) {
            AuthCredentials first=new AuthCredentials("Bearer","","first-token"), second=new AuthCredentials("Bearer","","second-token");
            String old=h.prepare(first), current=h.prepare(second); assertNotEquals(old,current);
            assertThrows(IllegalStateException.class,first::authorization); assertNull(h.take(old)); assertNull(h.take("unknown"));
            assertSame(second,h.take(current)); assertNull(h.take(current)); second.close();
        }
    }
    @Test public void abandonedCredentialHandoffClearsItsSecret() {
        AuthHandoff h=new AuthHandoff(); AuthCredentials c=new AuthCredentials("Basic","fixture","password"); String token=h.prepare(c); h.close();
        assertNull(h.take(token)); assertThrows(IllegalStateException.class,c::authorization);
    }
    @Test public void v020HistoryDeserializesWithNewProbesAndAuthenticationOff() throws Exception {
        try(ObjectInputStream in=new ObjectInputStream(getClass().getResourceAsStream("/legacy-v020.report"))) {
            ScanReport r=(ScanReport)in.readObject(); assertEquals("0.2.0",r.version()); assertTrue(r.config.http(8089)); assertFalse(r.config.protocolChecks); assertFalse(r.config.enumerateTls); assertFalse(r.config.authenticated()); assertNull(r.config.extraRedisPorts);
            Map<String,Object> config=JsonReader.object(JsonReader.object(JsonReader.parse(ReportExporter.json(r))).get("configuration")); assertEquals("None",config.get("authMethod")); assertEquals(0,JsonReader.integer(config.get("authPort")));
        }
    }
    @Test public void comparisonRejectsChangedProtocolScopeAndUnrecordedCredentialIdentity() {
        ScanReport a=new ScanReport(config(16379,"","Redis",false,"None")), b=new ScanReport(new ScanConfig("127.0.0.1","","Custom","16379",1000,1)); a.status=b.status="Completed";
        assertThrows(IllegalArgumentException.class,()->ReportDiff.compare(a,b));
        ScanReport auth=new ScanReport(config(9443,"localhost","HTTPS",false,"Basic")); auth.status="Completed";
        assertThrows(IllegalArgumentException.class,()->ReportDiff.compare(auth,auth));
    }
}
