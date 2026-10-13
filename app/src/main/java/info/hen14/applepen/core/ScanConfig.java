package info.hen14.applepen.core;

import java.io.Serializable;
import java.net.IDN;
import java.net.InetAddress;
import java.net.Inet6Address;
import java.util.ArrayList;
import java.util.TreeSet;

/** Immutable scope. Only a literal single IP is ever used as a socket destination. */
public final class ScanConfig implements Serializable {
    private static final long serialVersionUID = 1L;
    public static final String QUICK_PORTS = "21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,587,636,993,995,1433,1521,2049,2375,2376,3000,3306,3389,5000,5432,5672,5900,5985,5986,6379,6443,8000,8008,8080,8081,8443,8888,9000,9090,9200,9300,11211,27017";
    public final String ip, hostname, profile;
    public final ArrayList<Integer> ports;
    public final int timeoutMs, concurrency;
    public final long budgetMs;
    public final ArrayList<Integer> extraHttpPorts, extraHttpsPorts;
    public final boolean lookupCves;
    public final boolean protocolChecks, enumerateTls;
    public final ArrayList<Integer> extraRedisPorts, extraPostgresPorts;
    // Authentication metadata only. Credentials never enter this serializable scope.
    public final String authMethod;
    public final int authPort;
    public ScanConfig(String ip, String hostname, String profile, String ports, int timeoutMs, int concurrency) {
        this(ip, hostname, profile, ports, timeoutMs, concurrency, "", "", false);
    }
    public ScanConfig(String ip, String hostname, String profile, String ports, int timeoutMs, int concurrency, String httpPorts, String httpsPorts, boolean lookupCves) {
        this(ip,hostname,profile,ports,timeoutMs,concurrency,httpPorts,httpsPorts,lookupCves,false,"","",false,"None",0);
    }
    public ScanConfig(String ip, String hostname, String profile, String ports, int timeoutMs, int concurrency, String httpPorts, String httpsPorts, boolean lookupCves, boolean protocolChecks, String redisPorts, String postgresPorts, boolean enumerateTls, String authMethod, int authPort) {
        this.ip = validateIp(ip);
        this.hostname = validateHostname(hostname);
        this.profile = profile;
        this.ports = parsePorts(ports);
        if (timeoutMs < 200 || timeoutMs > 5000) throw new IllegalArgumentException("Timeout must be 200–5000 ms.");
        if (concurrency < 1 || concurrency > 24) throw new IllegalArgumentException("Connections must be 1–24.");
        this.timeoutMs = timeoutMs;
        this.concurrency = concurrency;
        this.budgetMs = 20 * 60 * 1000L;
        this.extraHttpPorts = optionalPorts(httpPorts);
        this.extraHttpsPorts = optionalPorts(httpsPorts);
        this.lookupCves = lookupCves;
        this.protocolChecks = protocolChecks; this.enumerateTls = enumerateTls;
        this.extraRedisPorts = optionalPorts(redisPorts); this.extraPostgresPorts = optionalPorts(postgresPorts);
        this.authMethod = authMethod == null ? "None" : authMethod;
        this.authPort = authPort;
        if (!java.util.Set.of("None","Basic","Bearer").contains(this.authMethod)) throw new IllegalArgumentException("Choose None, Basic, or Bearer authentication.");
        if (authenticated() && (!this.ports.contains(authPort) || !https(authPort))) throw new IllegalArgumentException("Authentication needs one selected HTTPS port. Assign an additional HTTPS port if necessary.");
        if (!authenticated() && authPort != 0) throw new IllegalArgumentException("Authentication port must be empty when authentication is off.");
        if (extraHttpPorts.size() + extraHttpsPorts.size() + extraRedisPorts.size() + extraPostgresPorts.size() > 32) throw new IllegalArgumentException("Select at most 32 additional protocol ports.");
        if (!this.ports.containsAll(extraHttpPorts) || !this.ports.containsAll(extraHttpsPorts)) throw new IllegalArgumentException("Additional HTTP/HTTPS ports must also be in the TCP scan selection.");
        for (int p : extraHttpPorts) if (extraHttpsPorts.contains(p) || defaultTls(p)) throw new IllegalArgumentException("TCP " + p + " is already assigned to TLS/HTTPS.");
        for (int p : extraHttpsPorts) if (defaultHttp(p)) throw new IllegalArgumentException("TCP " + p + " is already assigned to HTTP.");
        if (!this.ports.containsAll(extraRedisPorts) || !this.ports.containsAll(extraPostgresPorts)) throw new IllegalArgumentException("Additional Redis/PostgreSQL ports must also be in the TCP scan selection.");
        if (!protocolChecks && (!extraRedisPorts.isEmpty() || !extraPostgresPorts.isEmpty())) throw new IllegalArgumentException("Enable protocol checks to assign Redis/PostgreSQL ports.");
        for (int p : extraRedisPorts) if (http(p) || tls(p) || p == 5432 || p == 25 || p == 587 || extraPostgresPorts.contains(p)) throw new IllegalArgumentException("TCP " + p + " has another protocol assignment.");
        for (int p : extraPostgresPorts) if (http(p) || tls(p) || p == 6379 || p == 25 || p == 587) throw new IllegalArgumentException("TCP " + p + " has another protocol assignment.");
        if (protocolChecks) for (int p : extraHttpPorts) if (p == 6379 || p == 5432 || p == 25 || p == 587) throw new IllegalArgumentException("TCP " + p + " has another protocol assignment.");
        if (protocolChecks) for (int p : extraHttpsPorts) if (p == 6379 || p == 5432 || p == 25 || p == 587) throw new IllegalArgumentException("TCP " + p + " has another protocol assignment.");
    }
    private static ArrayList<Integer> optionalPorts(String s) { return s == null || s.trim().isEmpty() ? new ArrayList<>() : parsePorts(s); }
    public static boolean defaultHttp(int p) { return java.util.Set.of(80,3000,5000,5985,8000,8008,8080,8081,8888,9000,9090,9200).contains(p); }
    public static boolean defaultTls(int p) { return java.util.Set.of(443,465,636,993,995,2376,5986,8443).contains(p); }
    public boolean http(int p) { return defaultHttp(p) || (extraHttpPorts != null && extraHttpPorts.contains(p)); }
    public boolean https(int p) { return java.util.Set.of(443,2376,5986,8443).contains(p) || (extraHttpsPorts != null && extraHttpsPorts.contains(p)); }
    public boolean tls(int p) { return defaultTls(p) || https(p); }
    public boolean redis(int p) { return protocolChecks && (p == 6379 || extraRedisPorts != null && extraRedisPorts.contains(p)); }
    public boolean postgres(int p) { return protocolChecks && (p == 5432 || extraPostgresPorts != null && extraPostgresPorts.contains(p)); }
    public boolean authenticated() { return authMethod != null && !authMethod.equals("None"); }
    public String authentication() { return authenticated() ? authMethod + " on HTTPS TCP " + authPort : "Disabled"; }
    public static String validateIp(String value) {
        String ip = value == null ? "" : value.trim();
        try {
            if (ip.contains(":")) {
                if (!ip.matches("[0-9A-Fa-f:.]+(%[A-Za-z0-9_.-]+)?")) throw new IllegalArgumentException();
                if (!(InetAddress.getByName(ip) instanceof Inet6Address)) throw new IllegalArgumentException();
            } else {
                String[] parts = ip.split("\\.", -1);
                if (parts.length != 4) throw new IllegalArgumentException();
                for (String part : parts) {
                    if (!part.matches("[0-9]{1,3}") || Integer.parseInt(part) > 255 || (part.length() > 1 && part.startsWith("0"))) throw new IllegalArgumentException();
                }
            }
            return ip;
        } catch (Exception e) {
            throw new IllegalArgumentException("Enter one valid IPv4 or IPv6 address, without a URL or subnet.");
        }
    }
    public static String validateHostname(String value) {
        String input = value == null ? "" : value.trim();
        if (input.isEmpty()) return "";
        try {
            String host = IDN.toASCII(input, IDN.USE_STD3_ASCII_RULES).toLowerCase(java.util.Locale.ROOT);
            if (host.length() > 253 || host.contains(":") || host.contains("/") || host.contains("\n")) throw new IllegalArgumentException();
            if (host.endsWith(".")) host = host.substring(0, host.length() - 1);
            for (String label : host.split("\\.", -1)) {
                if (label.length() > 63 || !label.matches("[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")) throw new IllegalArgumentException();
            }
            return host;
        } catch (Exception e) { throw new IllegalArgumentException("Use a hostname such as server.example.com, without a scheme, path, or port."); }
    }
    public static ArrayList<Integer> parsePorts(String expression) {
        TreeSet<Integer> result = new TreeSet<>();
        if (expression == null || expression.trim().isEmpty()) throw new IllegalArgumentException("Enter ports or ranges, for example 22,80,443,8000-8010.");
        for (String item : expression.split(",", -1)) {
            String[] range = item.trim().split("-", -1);
            if (range.length < 1 || range.length > 2) throw new IllegalArgumentException("Invalid port range.");
            int start = port(range[0]);
            int end = range.length == 2 ? port(range[1]) : start;
            if (start > end) throw new IllegalArgumentException("Port range is reversed.");
            for (int p = start; p <= end; p++) result.add(p);
        }
        return new ArrayList<>(result);
    }
    private static int port(String value) {
        try {
            if (!value.trim().matches("[0-9]{1,5}")) throw new NumberFormatException();
            int p = Integer.parseInt(value.trim());
            if (p < 1 || p > 65535) throw new NumberFormatException();
            return p;
        } catch (NumberFormatException e) { throw new IllegalArgumentException("Ports must be between 1 and 65535."); }
    }
    public String identity() { return hostname.isEmpty() ? ip.split("%", 2)[0] : hostname; }
    public String hostHeader(int port, boolean tls) {
        String host = hostname.isEmpty() && ip.contains(":") ? "[" + ip.split("%", 2)[0] + "]" : identity();
        return host + ((tls && port == 443) || (!tls && port == 80) ? "" : ":" + port);
    }
}
