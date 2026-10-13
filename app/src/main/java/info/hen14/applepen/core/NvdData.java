package info.hen14.applepen.core;

import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class NvdData {
    private NvdData() { }
    public static String selectCpe(String json, ProductFingerprint fingerprint) {
        Map<String,Object> root = JsonReader.object(JsonReader.parse(json));
        if (!(root.get("products") instanceof List) || !(root.get("totalResults") instanceof Number)) throw new IllegalArgumentException("Invalid NVD dictionary response schema");
        for (Object item : JsonReader.array(root.get("products"))) {
            Map<String,Object> cpe = JsonReader.object(JsonReader.object(item).get("cpe"));
            String name = JsonReader.string(cpe.get("cpeName"));
            if (!Boolean.TRUE.equals(cpe.get("deprecated")) && fingerprint.matchesCpe(name)) return name;
        }
        return "";
    }
    public static CveLookup.Result findings(String json, ProductFingerprint product, String cpe, int port, String provenance) {
        Map<String,Object> root = JsonReader.object(JsonReader.parse(json));
        if (!(root.get("vulnerabilities") instanceof List) || !(root.get("totalResults") instanceof Number)) throw new IllegalArgumentException("Invalid NVD CVE response schema");
        CveLookup.Result result = new CveLookup.Result();
        int total = JsonReader.integer(root.get("totalResults"));
        List<?> records = JsonReader.array(root.get("vulnerabilities"));
        int processed = Math.min(20,records.size());
        for (int i=0;i<processed;i++) {
            Object item = records.get(i);
            Map<String,Object> cve = JsonReader.object(JsonReader.object(item).get("cve"));
            String id = JsonReader.string(cve.get("id"));
            if (!id.matches("CVE-[0-9]{4}-[0-9]{4,}") || "Rejected".equalsIgnoreCase(JsonReader.string(cve.get("vulnStatus")))) continue;
            String description = "Review the NVD record and vendor advisory for applicability.";
            for (Object desc : JsonReader.array(cve.get("descriptions"))) {
                Map<String,Object> d = JsonReader.object(desc);
                if ("en".equals(d.get("lang"))) { description = JsonReader.string(d.get("value")); break; }
            }
            Map<String,Object> metrics = JsonReader.object(cve.get("metrics")), metric = Map.of();
            for (String key : new String[]{"cvssMetricV40","cvssMetricV31","cvssMetricV30","cvssMetricV2"}) {
                List<?> values = JsonReader.array(metrics.get(key));
                if (!values.isEmpty()) { metric = JsonReader.object(values.get(0)); for (Object value : values) if ("Primary".equals(JsonReader.object(value).get("type"))) { metric = JsonReader.object(value); break; } break; }
            }
            Map<String,Object> score = JsonReader.object(metric.get("cvssData"));
            String severity = JsonReader.string(score.get("baseSeverity")); if (severity.isEmpty()) severity = JsonReader.string(metric.get("baseSeverity"));
            severity = switch(severity.toUpperCase(Locale.ROOT)) { case "CRITICAL" -> "Critical"; case "HIGH" -> "High"; case "MEDIUM" -> "Medium"; case "LOW" -> "Low"; default -> "Info"; };
            String evidence = "Detected banner product: " + product.query() + "\nNVD dictionary name: " + cpe + "\nNVD record: " + id + "\nCVSS base score: " + (score.get("baseScore") == null ? "Not supplied" : score.get("baseScore")) + "\n" + provenance;
            result.findings.add(new ScanReport.Finding("Potential CVE · " + id + " · " + product.name,severity,"Low","Potential CVE",port,evidence,
                HttpRules.clean(description) + " Banner identity, vendor backports, platform prerequisites, and exploitability have not been verified.",
                "Check the vendor advisory and installed package/build. Apply a relevant vendor fix if affected; do not infer vulnerability solely from the banner.","https://nvd.nist.gov/vuln/detail/" + id));
        }
        result.coverage.add("TCP " + port + ": NVD returned " + total + " candidate records for " + product.query() + "; processed " + processed + ". " + provenance);
        if (total > processed || records.size() > processed) result.coverage.add("NVD results were capped at one 20-record page for " + product.query() + "; this is not exhaustive CVE coverage.");
        result.coverage.add("CVE candidates use NVD's cpeName/isVulnerable filter and an exact dictionary version match. They do not confirm installed software, vendor patch status, or applicability of all configuration prerequisites.");
        return result;
    }
}
