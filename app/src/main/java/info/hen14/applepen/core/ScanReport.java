package info.hen14.applepen.core;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.UUID;

public final class ScanReport implements Serializable {
    private static final long serialVersionUID = 1L;
    public final String id = UUID.randomUUID().toString();
    public final ScanConfig config;
    public final long startedAt = System.currentTimeMillis();
    public long finishedAt;
    public String status = "Running", network = "Unknown", error = "";
    public int attempted, closed, timedOut, failed;
    public String scannerVersion = AppVersion.VERSION;
    public final ArrayList<Integer> refusedPorts = new ArrayList<>(), timeoutPorts = new ArrayList<>(), errorPorts = new ArrayList<>();
    public ReportDiff comparison;
    public final ArrayList<Port> ports = new ArrayList<>();
    public final ArrayList<Finding> findings = new ArrayList<>();
    public final ArrayList<String> coverage = new ArrayList<>();
    public ScanReport(ScanConfig config) { this.config = config; }
    public static final class Port implements Serializable {
        private static final long serialVersionUID = 1L;
        public final int number;
        public String service = "Unidentified TCP service", evidence = "TCP connection succeeded.";
        public Port(int number) { this.number = number; }
    }
    public static final class Finding implements Serializable {
        private static final long serialVersionUID = 1L;
        public final String title, severity, confidence, status, evidence, impact, remediation, reference;
        public final int port;
        public Finding(String title, String severity, String confidence, String status, int port, String evidence, String impact, String remediation, String reference) {
            this.title = title; this.severity = severity; this.confidence = confidence; this.status = status;
            this.port = port; this.evidence = evidence; this.impact = impact;
            this.remediation = remediation; this.reference = reference;
        }
    }
    public int count(String severity) { int n = 0; for (Finding f : findings) if (f.severity.equals(severity)) n++; return n; }
    public String summary() { return ports.size() + " open ports · " + findings.size() + " findings · " + status; }
    public String version() { return scannerVersion == null ? "0.1.0" : scannerVersion; }
}
