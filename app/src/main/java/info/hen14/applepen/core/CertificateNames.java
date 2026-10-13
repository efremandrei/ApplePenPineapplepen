package info.hen14.applepen.core;

import java.net.InetAddress;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

public final class CertificateNames {
    private CertificateNames() { }
    public static boolean matches(X509Certificate certificate, String identity) {
        try {
            Collection<List<?>> names = certificate.getSubjectAlternativeNames();
            if (names == null) return false;
            boolean ip = identity.contains(":") || identity.matches("[0-9.]+");
            for (List<?> name : names) {
                if (name.size() < 2) continue;
                if (ip && Integer.valueOf(7).equals(name.get(0)) && name.get(1) instanceof String && InetAddress.getByName(identity).equals(InetAddress.getByName((String) name.get(1)))) return true;
                if (!ip && Integer.valueOf(2).equals(name.get(0)) && name.get(1) instanceof String && dnsMatches((String) name.get(1), identity)) return true;
            }
        } catch (Exception ignored) { }
        return false;
    }
    public static boolean dnsMatches(String pattern, String host) {
        pattern = pattern.toLowerCase(Locale.ROOT); host = host.toLowerCase(Locale.ROOT);
        if (!pattern.startsWith("*.")) return pattern.equals(host);
        String suffix = pattern.substring(1);
        if (!host.endsWith(suffix)) return false;
        String prefix = host.substring(0, host.length() - suffix.length());
        return !prefix.isEmpty() && !prefix.contains(".");
    }
}
