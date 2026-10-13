package info.hen14.applepen.core;

import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

public final class HttpRules {
    private static final String WSTG = "https://owasp.org/www-project-web-security-testing-guide/";
    private HttpRules() { }
    public static void evaluate(HttpResponse response, int port, boolean tls, List<ScanReport.Finding> findings) {
        if (!tls) add(findings, "HTTP service permits unencrypted transport", "Low", "High", "Observed", port,
            response.statusLine + "; plaintext connection succeeded.", "Traffic to this endpoint can be read or altered on the network. Impact depends on the content and redirects.", "Use HTTPS for sensitive traffic and redirect HTTP to HTTPS.");
        String type = response.header("content-type").toLowerCase(Locale.ROOT);
        boolean page = response.code >= 200 && response.code < 300 && (type.contains("text/html") || response.body.toLowerCase(Locale.ROOT).contains("<html"));
        if (page) {
            if (response.header("content-security-policy").isEmpty()) add(findings, "HTML response has no Content-Security-Policy", "Low", "High", "Observed", port,
                "No CSP header in the root response.", "A browser defense is absent; this does not demonstrate an injection vulnerability.", "Define a CSP appropriate for the application.");
            String csp = response.header("content-security-policy").toLowerCase(Locale.ROOT);
            if (response.header("x-frame-options").isEmpty() && !Pattern.compile("(?:^|;)\\s*frame-ancestors\\s+[^;]+", Pattern.CASE_INSENSITIVE).matcher(csp).find()) add(findings, "HTML response has no framing restriction", "Low", "High", "Observed", port,
                "Neither X-Frame-Options nor CSP frame-ancestors was present.", "Sensitive interactive pages may be exposed to clickjacking; application context is required.", "Set CSP frame-ancestors to an appropriate policy.");
            if (!response.header("x-content-type-options").equalsIgnoreCase("nosniff")) add(findings, "MIME sniffing defense is absent", "Low", "High", "Observed", port,
                "X-Content-Type-Options is missing or is not nosniff.", "Browsers may infer content types unexpectedly.", "Set X-Content-Type-Options: nosniff.");
            if (tls && response.header("strict-transport-security").isEmpty()) add(findings, "HTTPS HTML response has no HSTS", "Low", "High", "Observed", port,
                "No Strict-Transport-Security header in the root response.", "Browsers are not instructed by this response to require HTTPS for future visits.", "Deploy HSTS after verifying HTTPS across the intended hostname.");
            String body = response.body.toLowerCase(Locale.ROOT);
            if (Pattern.compile("<(?:title|h1)[^>]*>\\s*index of\\s", Pattern.CASE_INSENSITIVE).matcher(body).find()) add(findings, "Possible directory listing", "Medium", "Medium", "Suspected", port,
                "Root HTML title or heading resembles an Index of directory listing.", "A listing may reveal unintended files. The heading alone is not proof of exposure.", "Review the endpoint; disable automatic indexing if unintended.");
        }
        for (String cookie : response.cookies()) {
            String name = cookie.split("=", 2)[0].replaceAll("[^A-Za-z0-9_.-]", "?");
            String attributes = cookie.toLowerCase(Locale.ROOT);
            if (tls && !Pattern.compile("(?:^|;)\\s*secure\\s*(?:;|$)").matcher(attributes).find()) add(findings, "Cookie lacks Secure: " + name, "Low", "High", "Observed", port,
                "Set-Cookie for " + name + " lacks Secure. Value redacted.", "If this is a sensitive cookie, it may be transmitted over HTTP.", "Add Secure to sensitive cookies.");
            if (!Pattern.compile("(?:^|;)\\s*httponly\\s*(?:;|$)").matcher(attributes).find()) add(findings, "Cookie lacks HttpOnly: " + name, "Low", "High", "Observed", port,
                "Set-Cookie for " + name + " lacks HttpOnly. Value redacted.", "Scripts can read this cookie. Some non-sensitive cookies intentionally require script access.", "Use HttpOnly for session cookies that do not need JavaScript access.");
        }
        if (!response.header("server").isEmpty()) add(findings, "Server product header disclosed", "Info", "High", "Observed", port,
            "Server: " + clean(response.header("server")), "Product information is exposed. A banner does not establish a vulnerable version.", "Reduce unnecessary version details where practical.");
    }
    private static void add(List<ScanReport.Finding> findings, String title, String severity, String confidence, String status, int port, String evidence, String impact, String fix) {
        findings.add(new ScanReport.Finding(title, severity, confidence, status, port, evidence, impact, fix, WSTG));
    }
    public static String clean(String value) { return value.replaceAll("[\\p{Cntrl}&&[^\\n\\t]]", "?").substring(0, Math.min(500, value.length())); }
}
