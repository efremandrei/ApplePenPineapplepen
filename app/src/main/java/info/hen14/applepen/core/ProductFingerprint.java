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
        String[] fields = cpe.split(":",-1);
        if (fields.length != 13 || !fields[0].equals("cpe") || !fields[1].equals("2.3") || !fields[2].equals("a") || !vendors.contains(fields[3]) || !product.equals(fields[4])) return false;
        String update = fields[6].equals("*") || fields[6].equals("-") ? "" : fields[6];
        return normalize(fields[5] + update).equals(normalize(version));
    }
    private static String normalize(String s) { return s.toLowerCase(Locale.ROOT).replace("_","").replace("-",""); }
}
