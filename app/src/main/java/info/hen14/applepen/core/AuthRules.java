package info.hen14.applepen.core;

import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/** Only constant evidence and numeric counts survive. A response may reflect credentials. */
public final class AuthRules {
    private AuthRules() { }
    public static void evaluate(HttpResponse response, int port, List<ScanReport.Finding> findings) {
        boolean success = response.code >= 200 && response.code < 300;
        add(findings,port,"Authenticated HTTPS root response","Info","HTTP status " + response.code + ". Response text and header values omitted.",
            success ? "The supplied credential request received a successful HTTP response. This alone does not prove the application validated the credential." : "The request did not receive a successful response. Access acceptance and application security remain unverified.","Review the intended endpoint and account privileges.");
        if (success && response.header("content-type").toLowerCase(Locale.ROOT).contains("text/html")) {
            if (response.header("content-security-policy").isEmpty()) add(findings,port,"Authenticated HTML response has no CSP","Low","CSP header absent.","A browser defense is absent; no injection vulnerability was demonstrated.","Define a CSP appropriate for this page.");
            if (response.header("x-frame-options").isEmpty() && !Pattern.compile("(?:^|;)\\s*frame-ancestors\\s+[^;]+",Pattern.CASE_INSENSITIVE).matcher(response.header("content-security-policy")).find()) add(findings,port,"Authenticated HTML response has no framing restriction","Low","Framing headers absent.","Sensitive interactive pages may be exposed to clickjacking; application context is required.","Set an appropriate CSP frame-ancestors policy.");
            if (!response.header("x-content-type-options").equalsIgnoreCase("nosniff")) add(findings,port,"Authenticated HTML response lacks nosniff","Low","MIME sniffing defense absent.","Browsers may infer content types unexpectedly.","Set X-Content-Type-Options: nosniff.");
            if (response.header("strict-transport-security").isEmpty()) add(findings,port,"Authenticated HTML response has no HSTS","Low","HSTS header absent.","The response does not instruct browsers to require HTTPS for future visits.","Deploy HSTS after verifying HTTPS across the intended hostname.");
        }
        int secureMissing=0, httpOnlyMissing=0;
        for (String cookie : response.cookies()) {
            if (!Pattern.compile("(?:^|;)\\s*secure\\s*(?:;|$)",Pattern.CASE_INSENSITIVE).matcher(cookie).find()) secureMissing++;
            if (!Pattern.compile("(?:^|;)\\s*httponly\\s*(?:;|$)",Pattern.CASE_INSENSITIVE).matcher(cookie).find()) httpOnlyMissing++;
        }
        if (secureMissing > 0) add(findings,port,"Authenticated response cookies lack Secure","Low",secureMissing + " cookie(s) lack Secure; names and values omitted.","Sensitive cookies may be sent over HTTP.","Add Secure to sensitive cookies.");
        if (httpOnlyMissing > 0) add(findings,port,"Authenticated response cookies lack HttpOnly","Low",httpOnlyMissing + " cookie(s) lack HttpOnly; names and values omitted.","Scripts may access cookies; some intentionally require script access.","Use HttpOnly for session cookies where appropriate.");
    }
    private static void add(List<ScanReport.Finding> f,int port,String title,String severity,String evidence,String impact,String fix) { f.add(new ScanReport.Finding(title,severity,"High","Observed",port,evidence,impact,fix,"https://owasp.org/www-project-web-security-testing-guide/")); }
}
