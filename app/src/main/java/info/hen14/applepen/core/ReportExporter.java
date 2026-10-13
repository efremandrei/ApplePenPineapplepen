package info.hen14.applepen.core;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

public final class ReportExporter {
    private ReportExporter() { }
    public static String date(long time) {
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.ROOT);
        format.setTimeZone(TimeZone.getTimeZone("UTC")); return format.format(new Date(time));
    }
    public static List<String> text(ScanReport r) {
        ArrayList<String> lines = new ArrayList<>();
        lines.add("APPLEPEN · SECURITY ASSESSMENT"); lines.add("Target: " + r.config.ip);
        lines.add("Hostname: " + (r.config.hostname.isEmpty() ? "Not supplied" : r.config.hostname));
        lines.add("Status: " + r.status); lines.add("Started: " + date(r.startedAt));
        lines.add("Finished: " + (r.finishedAt > 0 ? date(r.finishedAt) : "Not recorded"));
        lines.add("Network viewpoint: " + r.network);
        lines.add("Profile: " + r.config.profile + "; timeout " + r.config.timeoutMs + " ms; concurrency " + r.config.concurrency);
        lines.add("Ports selected: " + r.config.ports.size() + "; processed: " + r.attempted + "; open: " + r.ports.size() + "; refused: " + r.closed + "; timed out: " + r.timedOut + "; errors: " + r.failed);
        if (!r.error.isEmpty()) lines.add("Error: " + r.error);
        lines.add("Additional HTTP ports: " + numbers(r.config.extraHttpPorts) + "; additional HTTPS ports: " + numbers(r.config.extraHttpsPorts));
        lines.add("NVD lookup: " + (r.config.lookupCves ? "Enabled · potential CVEs only" : "Disabled"));
        lines.add("Read-only protocol checks: " + r.config.protocolChecks + "; additional Redis: " + numbers(r.config.extraRedisPorts) + "; additional PostgreSQL: " + numbers(r.config.extraPostgresPorts));
        lines.add("TLS version probes: " + r.config.enumerateTls + "; credentialed HTTPS: " + r.config.authentication());
        lines.add("Scanner: ApplePen " + r.version());
        if (r.comparison != null) {
            lines.add(""); lines.add("COMPARISON"); lines.add("Baseline: " + date(r.comparison.baselineStartedAt) + "; report " + r.comparison.baselineId);
            lines.add(r.comparison.summary()); lines.addAll(r.comparison.changes); lines.addAll(r.comparison.caveats);
        }
        lines.add(""); lines.add("FINDINGS");
        if (r.findings.isEmpty()) lines.add("No findings from the completed checks. This is not proof that the target is secure.");
        for (ScanReport.Finding f : r.findings) {
            lines.add(f.severity.toUpperCase(Locale.ROOT) + " · TCP " + f.port + " · " + f.title);
            lines.add("Status: " + f.status + "; confidence: " + f.confidence);
            if(f.cve!=null) lines.add("CVE applicability: " + f.cve.applicability);
            lines.add("Evidence: " + f.evidence); lines.add("Impact: " + f.impact);
            lines.add("Remediation: " + f.remediation);
            if (!f.reference.isEmpty()) lines.add("Reference: " + f.reference);
            lines.add("");
        }
        lines.add("OPEN SERVICES");
        for (ScanReport.Port p : r.ports) { lines.add("TCP " + p.number + " · " + p.service); lines.add(p.evidence); }
        lines.add(""); lines.add("COVERAGE AND LIMITATIONS"); lines.addAll(r.coverage);
        lines.add("Report ID: " + r.id); lines.add("Scanner: ApplePen " + r.version());
        return lines;
    }
    public static String html(ScanReport r) {
        StringBuilder b = new StringBuilder("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>ApplePen assessment</title><style>body{font:16px system-ui,sans-serif;color:#142a34;background:#f5f7f8;margin:0;padding:32px;line-height:1.6}main{max-width:960px;margin:auto}header{background:#073940;color:white;padding:28px;border-radius:18px}h1{margin:0}article,section{background:white;border:1px solid #dce5e8;padding:22px;border-radius:14px;margin-top:18px}small{color:#52666e}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f5f6;padding:16px;border-radius:8px}td,th{text-align:left;padding:12px;border-bottom:1px solid #ddd}table{border-collapse:collapse;width:100%}.badge{font-weight:bold;color:#007e80}a{color:#007e80}p,li{overflow-wrap:anywhere}@media print{body{padding:0;background:white}article{break-inside:avoid}header{background:white;color:#073940}}</style><main><header><h1>ApplePen</h1><p>Network security assessment</p><strong>");
        b.append(escape(r.config.ip)).append("</strong><p>").append(escape(r.summary())).append("</p></header><section><h2>Scan context</h2>");
        List<String> context = text(r); for (int i=1;i<context.size() && !context.get(i).isEmpty();i++) b.append("<p>").append(escape(context.get(i))).append("</p>");
        b.append("</section>");
        if (r.comparison != null) { b.append("<section><h2>Comparison</h2><p>Baseline: ").append(escape(date(r.comparison.baselineStartedAt))).append("</p><strong>").append(escape(r.comparison.summary())).append("</strong><ul>"); for (String line:r.comparison.changes) b.append("<li>").append(escape(line)).append("</li>"); b.append("</ul>"); for (String line:r.comparison.caveats) b.append("<p>").append(escape(line)).append("</p>"); b.append("</section>"); }
        b.append("<h2>Findings</h2>");
        if (r.findings.isEmpty()) b.append("<section>No findings from the completed checks. This is not proof that the target is secure.</section>");
        for (ScanReport.Finding f : r.findings) {
            b.append("<article><span class=badge>").append(escape(f.severity)).append(" · TCP ").append(f.port).append("</span><h3>").append(escape(f.title)).append("</h3><small>").append(escape(f.status + " · confidence: " + f.confidence)).append("</small><h4>Evidence</h4><pre>").append(escape(f.evidence)).append("</pre><h4>Impact</h4><p>").append(escape(f.impact)).append("</p><h4>Remediation</h4><p>").append(escape(f.remediation)).append("</p>");
            if (f.reference.startsWith("https://")) b.append("<a rel=\"noopener noreferrer\" href=\"").append(escape(f.reference)).append("\">Reference</a>");
            b.append("</article>");
        }
        b.append("<section><h2>Open services</h2><table><tr><th>TCP port</th><th>Service</th><th>Evidence</th></tr>");
        for (ScanReport.Port p : r.ports) b.append("<tr><td>").append(p.number).append("</td><td>").append(escape(p.service)).append("</td><td><pre>").append(escape(p.evidence)).append("</pre></td></tr>");
        b.append("</table></section><section><h2>Coverage and limitations</h2><ul>");
        for (String line : r.coverage) b.append("<li>").append(escape(line)).append("</li>");
        return b.append("</ul><small>ApplePen ").append(escape(r.version())).append(" · Report ").append(escape(r.id)).append("</small></section></main></html>").toString();
    }
    public static String escape(String s) { return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;"); }
    public static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) { case '"' -> b.append("\\\""); case '\\' -> b.append("\\\\"); case '\n' -> b.append("\\n"); case '\r' -> b.append("\\r"); case '\t' -> b.append("\\t"); default -> { if (c < 32) b.append(String.format(Locale.ROOT,"\\u%04x", (int)c)); else b.append(c); } }
        }
        return b.append('"').toString();
    }
    public static String json(ScanReport r) {
        StringBuilder b = new StringBuilder("{\"schemaVersion\":4,\"scanner\":"); b.append(quote("ApplePen " + r.version())).append(",\"id\":");
        b.append(quote(r.id)).append(",\"targetIp\":").append(quote(r.config.ip)).append(",\"hostname\":").append(quote(r.config.hostname)).append(",\"status\":").append(quote(r.status)).append(",\"network\":").append(quote(r.network)).append(",\"startedAt\":").append(r.startedAt).append(",\"finishedAt\":").append(r.finishedAt).append(",\"error\":").append(quote(r.error));
        b.append(",\"configuration\":{\"profile\":").append(quote(r.config.profile)).append(",\"timeoutMs\":").append(r.config.timeoutMs).append(",\"concurrency\":").append(r.config.concurrency).append(",\"budgetMs\":").append(r.config.budgetMs).append(",\"selectedPorts\":").append(r.config.ports).append(",\"additionalHttpPorts\":").append(numbers(r.config.extraHttpPorts)).append(",\"additionalHttpsPorts\":").append(numbers(r.config.extraHttpsPorts)).append(",\"lookupCves\":").append(r.config.lookupCves).append(",\"protocolChecks\":").append(r.config.protocolChecks).append(",\"additionalRedisPorts\":").append(numbers(r.config.extraRedisPorts)).append(",\"additionalPostgresPorts\":").append(numbers(r.config.extraPostgresPorts)).append(",\"enumerateTls\":").append(r.config.enumerateTls).append(",\"authMethod\":").append(quote(r.config.authenticated() ? r.config.authMethod : "None")).append(",\"authPort\":").append(r.config.authPort).append("},\"counts\":{\"attempted\":").append(r.attempted).append(",\"open\":").append(r.ports.size()).append(",\"closed\":").append(r.closed).append(",\"timedOut\":").append(r.timedOut).append(",\"errors\":").append(r.failed).append("},\"refusedPorts\":").append(numbers(r.refusedPorts)).append(",\"timeoutPorts\":").append(numbers(r.timeoutPorts)).append(",\"errorPorts\":").append(numbers(r.errorPorts)).append(",\"services\":[");
        boolean first = true;
        for (ScanReport.Port p : r.ports) { if (!first) b.append(','); first = false; b.append("{\"port\":").append(p.number).append(",\"transport\":\"tcp\",\"state\":\"open\",\"service\":").append(quote(p.service)).append(",\"evidence\":").append(quote(p.evidence)).append('}'); }
        b.append("],\"findings\":["); first = true;
        for (ScanReport.Finding f : r.findings) {
            if (!first) b.append(','); first = false;
            b.append("{\"port\":").append(f.port).append(",\"title\":").append(quote(f.title)).append(",\"severity\":").append(quote(f.severity)).append(",\"confidence\":").append(quote(f.confidence)).append(",\"status\":").append(quote(f.status)).append(",\"evidence\":").append(quote(f.evidence)).append(",\"impact\":").append(quote(f.impact)).append(",\"remediation\":").append(quote(f.remediation)).append(",\"reference\":").append(quote(f.reference)).append(",\"cveAssessment\":").append(cveJson(f.cve)).append('}');
        }
        b.append("],\"coverage\":["); first = true;
        for (String line : r.coverage) { if (!first) b.append(','); first = false; b.append(quote(line)); }
        b.append("],\"comparison\":");
        if (r.comparison == null) b.append("null");
        else { ReportDiff d = r.comparison; b.append("{\"baselineId\":").append(quote(d.baselineId)).append(",\"baselineStartedAt\":").append(d.baselineStartedAt).append(",\"newFindings\":").append(d.newFindings).append(",\"missingFindings\":").append(d.missingFindings).append(",\"retainedFindings\":").append(d.retainedFindings).append(",\"changedFindings\":").append(d.changedFindings).append(",\"changes\":").append(strings(d.changes)).append(",\"caveats\":").append(strings(d.caveats)).append('}'); }
        return b.append('}').toString();
    }
    private static String cveJson(CveAssessment c) {
        return c==null ? "null" : "{\"product\":" + quote(c.product) + ",\"version\":" + quote(c.version) + ",\"dictionaryCpe\":" + quote(c.dictionaryCpe) + ",\"applicability\":" + quote(c.applicability) + ",\"reason\":" + quote(c.reason) + ",\"rules\":" + strings(c.rules) + "}";
    }
    private static String numbers(List<Integer> values) { return values == null ? "[]" : values.toString(); }
    private static String strings(List<String> values) { StringBuilder b = new StringBuilder("["); for (String value : values) { if (b.length()>1) b.append(','); b.append(quote(value)); } return b.append(']').toString(); }
}
