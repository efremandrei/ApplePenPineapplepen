package info.hen14.applepen;

import info.hen14.applepen.core.CveLookup;
import info.hen14.applepen.core.AppVersion;
import info.hen14.applepen.core.NvdData;
import info.hen14.applepen.core.ProductFingerprint;
import info.hen14.applepen.core.ReportExporter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.concurrent.atomic.AtomicBoolean;

/** Optional NVD queries with ordinary HTTPS verification. Only product/version data is sent. */
public final class NvdClient implements CveLookup {
    private static final String BASE = "https://services.nvd.nist.gov/rest/json/";
    private static long nextRequest;
    private static final Object RATE_LOCK = new Object();
    private final File cache;
    private final AtomicBoolean cancelled = new AtomicBoolean();
    private volatile HttpURLConnection current;
    public NvdClient(File cacheDirectory) { cache = new File(cacheDirectory,"nvd"); }
    @Override public void cancel() { cancelled.set(true); HttpURLConnection c = current; if (c != null) c.disconnect(); }
    private void check() throws InterruptedException { if (cancelled.get() || Thread.currentThread().isInterrupted()) throw new InterruptedException("Lookup cancelled"); }
    private void rateLimit() throws InterruptedException {
        while (true) {
            check();
            synchronized (RATE_LOCK) { long now = System.nanoTime()/1000000; if (now >= nextRequest) { nextRequest = now + 7000; return; } }
            Thread.sleep(100);
        }
    }
    private static final class Response { final String text, provenance; Response(String text,String provenance) { this.text = text; this.provenance = provenance; } }
    private Response fetch(String path) throws Exception {
        check(); if (!cache.exists() && !cache.mkdirs()) throw new IllegalStateException("Cannot create NVD cache");
        String hash = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(path.getBytes(StandardCharsets.UTF_8)));
        File file = new File(cache,hash + ".json");
        long age = System.currentTimeMillis()-file.lastModified();
        if (file.exists() && file.length() <= 524288 && age >= 0 && age < 24*60*60*1000L) return new Response(new String(Files.readAllBytes(file.toPath()),StandardCharsets.UTF_8),"NVD cache fetched " + ReportExporter.date(file.lastModified()) + "; cache TTL 24 hours.");
        rateLimit(); check();
        HttpURLConnection connection = (HttpURLConnection)new URL(BASE + path).openConnection(); current = connection;
        connection.setConnectTimeout(8000); connection.setReadTimeout(8000); connection.setInstanceFollowRedirects(false);
        connection.setRequestProperty("Accept","application/json"); connection.setRequestProperty("User-Agent","ApplePen/" + AppVersion.VERSION);
        try {
            int status = connection.getResponseCode();
            if (status != 200) throw new IllegalStateException("NVD HTTP " + status + (status == 403 || status == 429 ? " (access/rate limit; try later)" : ""));
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            try (InputStream input = connection.getInputStream()) {
                byte[] bytes = new byte[4096]; int read;
                long deadline = System.nanoTime() + 15_000_000_000L;
                while ((read = input.read(bytes)) != -1) { check(); if (System.nanoTime() > deadline || body.size()+read > 524288) throw new IllegalStateException("NVD response limit exceeded"); body.write(bytes,0,read); }
            }
            String text = new String(body.toByteArray(),StandardCharsets.UTF_8);
            info.hen14.applepen.core.JsonReader.parse(text);
            try {
                File temp = new File(cache,hash + ".tmp"); Files.write(temp.toPath(),text.getBytes(StandardCharsets.UTF_8));
                Files.move(temp.toPath(),file.toPath(),StandardCopyOption.REPLACE_EXISTING);
                File[] files = cache.listFiles((dir,name) -> name.endsWith(".json"));
                if (files != null && files.length > 40) { java.util.Arrays.sort(files,java.util.Comparator.comparingLong(File::lastModified)); for (int i=0;i<files.length-40;i++) files[i].delete(); }
            } catch (Exception ignored) { /* A cache failure does not discard a reviewed response. */ }
            return new Response(text,"NVD fetched " + ReportExporter.date(System.currentTimeMillis()) + ".");
        } finally { current = null; connection.disconnect(); }
    }
    @Override public Result lookup(ProductFingerprint product,int port) throws Exception {
        String query = URLEncoder.encode(product.query(),StandardCharsets.UTF_8.name());
        Response dictionary = fetch("cpes/2.0?keywordSearch=" + query + "&resultsPerPage=20");
        String cpe = NvdData.selectCpe(dictionary.text,product);
        if (cpe.isEmpty()) { Result r = new Result(); r.coverage.add("TCP " + port + ": no exact, non-deprecated CPE version matched the first 20 dictionary results for " + product.query() + ". CVE applicability was not inferred. " + dictionary.provenance); return r; }
        Response cves = fetch("cves/2.0?cpeName=" + URLEncoder.encode(cpe,StandardCharsets.UTF_8.name()) + "&isVulnerable&noRejected&resultsPerPage=20");
        return NvdData.findings(cves.text,product,cpe,port,dictionary.provenance + " " + cves.provenance);
    }
}
