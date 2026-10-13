package info.hen14.applepen.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Bounded root-page observation. Redirects and resources are never followed. */
public final class HttpResponse {
    public int code;
    public String statusLine = "", body = "";
    public final Map<String, List<String>> headers = new LinkedHashMap<>();
    public boolean truncated;
    public static HttpResponse read(InputStream in) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int match = 0;
        while (buffer.size() < 16384) {
            int b = in.read();
            if (b == -1) break;
            buffer.write(b);
            match = (match == 0 && b == '\r') ? 1 : (match == 1 && b == '\n') ? 2 : (match == 2 && b == '\r') ? 3 : (match == 3 && b == '\n') ? 4 : (b == '\r' ? 1 : 0);
            if (match == 4) break;
        }
        String head = new String(buffer.toByteArray(), StandardCharsets.ISO_8859_1);
        if (match != 4) throw new IOException("No complete HTTP headers within 16 KiB.");
        String[] lines = head.split("\r\n");
        HttpResponse response = new HttpResponse();
        response.statusLine = lines[0];
        if (!response.statusLine.matches("HTTP/1\\.[01] [0-9]{3}.*")) throw new IOException("Not an HTTP/1.x response.");
        response.code = Integer.parseInt(response.statusLine.substring(9, 12));
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon > 0) response.headers.computeIfAbsent(lines[i].substring(0, colon).toLowerCase(Locale.ROOT), key -> new ArrayList<>()).add(lines[i].substring(colon + 1).trim());
        }
        if (!response.header("content-encoding").isEmpty() && !response.header("content-encoding").equalsIgnoreCase("identity")) {
            response.truncated = true; return response;
        }
        int expected = 8192;
        try { if (!response.header("content-length").isEmpty()) expected = Math.min(8192, Math.max(0, Integer.parseInt(response.header("content-length")))); } catch (NumberFormatException ignored) { }
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        byte[] bytes = new byte[1024];
        while (body.size() < expected) {
            int n;
            try { n = in.read(bytes, 0, Math.min(bytes.length, expected - body.size())); }
            catch (java.net.SocketTimeoutException e) { response.truncated = true; break; }
            if (n == -1) break;
            body.write(bytes, 0, n);
        }
        response.body = new String(body.toByteArray(), StandardCharsets.UTF_8);
        response.truncated |= body.size() == 8192 || response.header("transfer-encoding").toLowerCase(Locale.ROOT).contains("chunked");
        return response;
    }
    public String header(String name) { List<String> values = headers.get(name.toLowerCase(Locale.ROOT)); return values == null ? "" : String.join(", ", values); }
    public List<String> cookies() { return headers.getOrDefault("set-cookie", new ArrayList<>()); }
}
