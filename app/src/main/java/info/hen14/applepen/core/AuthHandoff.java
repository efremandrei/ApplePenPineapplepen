package info.hen14.applepen.core;

import java.util.UUID;

/** Single pending in-process credential, bound to an opaque per-start token. */
public final class AuthHandoff implements AutoCloseable {
    private AuthCredentials pending;
    private String token = "";
    public synchronized String prepare(AuthCredentials credentials) {
        close(); pending = credentials;
        token = credentials == null ? "" : UUID.randomUUID().toString(); return token;
    }
    public synchronized AuthCredentials take(String requested) {
        if (requested == null || requested.isEmpty() || !requested.equals(token)) return null;
        AuthCredentials result = pending; pending = null; token = ""; return result;
    }
    @Override public synchronized void close() { if (pending != null) pending.close(); pending = null; token = ""; }
}
