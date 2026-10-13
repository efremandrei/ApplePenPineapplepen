package info.hen14.applepen.core;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/** Ephemeral, deliberately not Serializable. Never attach this object to a report. */
public final class AuthCredentials implements AutoCloseable {
    private final String method;
    private char[] username, secret;
    public AuthCredentials(String method, String username, String secret) {
        if (!"Basic".equals(method) && !"Bearer".equals(method)) throw new IllegalArgumentException("Choose Basic or Bearer authentication.");
        if (secret == null || secret.isEmpty() || secret.length() > 8192 || secret.matches("(?s).*[\\p{Cntrl}].*")) throw new IllegalArgumentException("Enter a credential of 1–8192 characters without control characters.");
        if ("Basic".equals(method) && (username == null || username.isEmpty() || username.length() > 256 || username.contains(":") || username.matches("(?s).*[\\p{Cntrl}].*"))) throw new IllegalArgumentException("Basic authentication needs a username without colons or control characters.");
        if ("Bearer".equals(method) && !secret.matches("[A-Za-z0-9._~+/-]+=*")) throw new IllegalArgumentException("Enter a valid Bearer token without spaces.");
        this.method = method; this.username = ("Basic".equals(method) ? username : "").toCharArray(); this.secret = secret.toCharArray();
    }
    public boolean matches(String method) { return this.method.equals(method) && secret.length > 0; }
    public synchronized String authorization() {
        if (secret.length == 0) throw new IllegalStateException("Credential was cleared");
        if (method.equals("Bearer")) return "Bearer " + new String(secret);
        byte[] bytes = (new String(username) + ":" + new String(secret)).getBytes(StandardCharsets.UTF_8);
        try { return "Basic " + Base64.getEncoder().encodeToString(bytes); }
        finally { Arrays.fill(bytes,(byte)0); }
    }
    @Override public synchronized void close() { Arrays.fill(username,'\0'); Arrays.fill(secret,'\0'); username = new char[0]; secret = new char[0]; }
}
