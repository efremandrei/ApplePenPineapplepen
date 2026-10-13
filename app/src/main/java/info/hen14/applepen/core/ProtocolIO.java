package info.hen14.applepen.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Strict, bounded parsers for the limited read-only probes. */
public final class ProtocolIO {
    private ProtocolIO() { }
    public static String line(InputStream in, int limit) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        while (bytes.size() < limit) {
            int b = in.read();
            if (b < 0) throw new IOException("Incomplete protocol line");
            bytes.write(b);
            if (b == '\n') {
                byte[] value = bytes.toByteArray();
                if (value.length < 2 || value[value.length-2] != '\r') throw new IOException("Expected CRLF");
                return new String(value,0,value.length-2,StandardCharsets.UTF_8);
            }
        }
        throw new IOException("Protocol line exceeds limit");
    }
    public static String redis(InputStream in) throws IOException {
        String first = line(in,1024);
        if (first.startsWith("+") || first.startsWith("-")) return first;
        if (!first.matches("\\$[0-9]{1,5}")) throw new IOException("Unsupported RESP response");
        int size = Integer.parseInt(first.substring(1));
        if (size > 16384) throw new IOException("RESP response exceeds 16 KiB");
        byte[] bytes = new byte[size]; int offset = 0;
        while (offset < size) { int n = in.read(bytes,offset,size-offset); if (n < 0) throw new IOException("Incomplete RESP body"); offset += n; }
        if (in.read() != '\r' || in.read() != '\n') throw new IOException("Incomplete RESP terminator");
        return "$" + new String(bytes,StandardCharsets.UTF_8);
    }
    public static List<String> smtp(InputStream in, int expected) throws IOException {
        List<String> lines = new ArrayList<>(); int remaining = 8192;
        for (int i=0;i<16;i++) {
            String value = line(in,Math.min(1024,remaining)); remaining -= value.getBytes(StandardCharsets.UTF_8).length + 2;
            if (!value.matches("[0-9]{3}[ -].*")) throw new IOException("Invalid SMTP reply");
            if (Integer.parseInt(value.substring(0,3)) != expected) throw new IOException("Unexpected SMTP reply code");
            lines.add(value);
            if (value.charAt(3) == ' ') return lines;
            if (remaining <= 0) break;
        }
        throw new IOException("SMTP reply exceeds limit");
    }
}
