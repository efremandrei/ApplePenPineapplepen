package info.hen14.applepen.core;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class ProductFingerprint {
    public final String name, version, product;
    private final Set<String> vendors;
    private ProductFingerprint(String name, String version, String product, Set<String> vendors) { this.name = name; this.version = version; this.product = product; this.vendors = vendors; }
    public static ProductFingerprint detect(String evidence) {
        String version = "([0-9]+(?:\\.[0-9]+){1,3}(?:p[0-9]+)?)";
        Matcher ssh = Pattern.compile("^SSH-(?:2\\.0|1\\.99|1\\.5)-OpenSSH_" + version + "(?:[\\s_-]|$)",Pattern.CASE_INSENSITIVE).matcher(evidence);
        if (ssh.find()) return new ProductFingerprint("OpenSSH",ssh.group(1),"openssh",Set.of("openbsd"));
        version = "([0-9]+(?:\\.[0-9]+){1,3})";
        Matcher nginx = Pattern.compile("(?im)^Server:\\s*nginx/" + version + "(?:[\\s;]|$)").matcher(evidence);
        if (nginx.find()) return new ProductFingerprint("nginx",nginx.group(1),"nginx",Set.of("nginx","f5"));
        Matcher apache = Pattern.compile("(?im)^Server:\\s*Apache/" + version + "(?:[\\s;]|$)").matcher(evidence);
        if (apache.find()) return new ProductFingerprint("Apache HTTP Server",apache.group(1),"http_server",Set.of("apache"));
        Matcher ftp = Pattern.compile("(?i)^220[^\\n]*vsftpd\\s+" + version + "(?:[\\s)]|$)").matcher(evidence);
        if (ftp.find()) return new ProductFingerprint("vsftpd",ftp.group(1),"vsftpd",Set.of("vsftpd"));
        return null;
    }
    public String query() { return name + " " + version; }
    public boolean matchesCpe(String cpe) {
        CpeName fields=CpeName.parse(cpe);
        if (fields==null || family(fields)!=1) return false;
        String update=fields.field(6);
        String version=fields.field(5);
        if (!update.equals("*") && !update.equals("-")) {
            if (!product.equals("openssh") || !update.matches("p[0-9]{1,9}") || VersionNumbers.parse(version)==null || VersionNumbers.parse(version).hasPortable()) return false;
            version+=update;
        }
        return VersionNumbers.parse(version)!=null && version.equals(this.version.toLowerCase(Locale.ROOT));
    }
    /** 1 = exact supported family, 0 = a different literal family, -1 = unsupported/wildcard. */
    public int family(CpeName fields) {
        if (!fields.literal(2) || !fields.literal(3) || !fields.literal(4)) return -1;
        return fields.field(2).equals("a") && vendors.contains(fields.field(3)) && product.equals(fields.field(4)) ? 1 : 0;
    }
}
