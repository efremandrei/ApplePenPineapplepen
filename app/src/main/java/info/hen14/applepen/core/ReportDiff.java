package info.hen14.applepen.core;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public final class ReportDiff implements Serializable {
    private static final long serialVersionUID = 1L;
    public final String baselineId;
    public final long baselineStartedAt;
    public final ArrayList<String> changes = new ArrayList<>(), caveats = new ArrayList<>();
    public int newFindings, missingFindings, retainedFindings, changedFindings;
    private ReportDiff(ScanReport baseline) { baselineId = baseline.id; baselineStartedAt = baseline.startedAt; }
    public static ReportDiff compare(ScanReport before, ScanReport after) {
        if (!before.config.ip.equals(after.config.ip) || !before.config.hostname.equals(after.config.hostname)) throw new IllegalArgumentException("Choose a report for the same IP and hostname.");
        if (!before.status.equals("Completed") || !after.status.equals("Completed")) throw new IllegalArgumentException("Comparison requires two completed scans. Cancelled, partial, and inconclusive results cannot establish changes.");
        if (!before.config.ports.equals(after.config.ports) || !extras(before.config.extraHttpPorts).equals(extras(after.config.extraHttpPorts)) || !extras(before.config.extraHttpsPorts).equals(extras(after.config.extraHttpsPorts)) || before.config.lookupCves != after.config.lookupCves) throw new IllegalArgumentException("Use the same TCP ports, protocol assignments, and CVE lookup setting for comparison.");
        if (before.config.authenticated() || after.config.authenticated()) throw new IllegalArgumentException("Credentialed reports cannot be compared because account identity is deliberately not retained.");
        if (before.config.protocolChecks != after.config.protocolChecks || before.config.enumerateTls != after.config.enumerateTls || !extras(before.config.extraRedisPorts).equals(extras(after.config.extraRedisPorts)) || !extras(before.config.extraPostgresPorts).equals(extras(after.config.extraPostgresPorts))) throw new IllegalArgumentException("Use the same protocol checks and TLS probe settings for comparison.");
        if (!Objects.equals(before.network, after.network)) throw new IllegalArgumentException("Network viewpoints differ. Rescan from the same connection type before comparing.");
        ReportDiff d = new ReportDiff(before);
        Map<String, ScanReport.Finding> old = findings(before), now = findings(after);
        for (Map.Entry<String,ScanReport.Finding> entry : now.entrySet()) {
            ScanReport.Finding previous = old.get(entry.getKey()), current = entry.getValue();
            if (previous == null) { d.newFindings++; d.changes.add("Newly observed · TCP " + current.port + " · " + current.title); }
            else if (!previous.severity.equals(current.severity) || !previous.status.equals(current.status) || !previous.confidence.equals(current.confidence) || !Objects.equals(previous.cve == null ? null : previous.cve.applicability,current.cve == null ? null : current.cve.applicability)) { d.changedFindings++; d.changes.add("Changed classification · TCP " + current.port + " · " + current.title); }
            else d.retainedFindings++;
        }
        for (Map.Entry<String,ScanReport.Finding> entry : old.entrySet()) if (!now.containsKey(entry.getKey())) { d.missingFindings++; d.changes.add("Not observed again · TCP " + entry.getValue().port + " · " + entry.getValue().title); }
        Set<Integer> oldPorts = openPorts(before), newPorts = openPorts(after);
        Set<Integer> refused = new HashSet<>(after.refusedPorts == null ? List.of() : after.refusedPorts);
        for (int p : new java.util.TreeSet<>(newPorts)) if (!oldPorts.contains(p)) d.changes.add("Newly reachable TCP port · " + p);
        for (int p : new java.util.TreeSet<>(oldPorts)) if (!newPorts.contains(p)) d.changes.add((refused.contains(p) ? "Previously open; now connection refused · " : "Previously open; current result inconclusive · ") + p);
        d.caveats.add("Not observed again does not mean fixed. Root responses, service inspection limits, timeouts, and source data may change detection coverage.");
        d.caveats.add("The connection type matches; this does not guarantee identical Wi-Fi topology, VPN routes, or firewall policy.");
        if (!before.version().equals(after.version())) d.caveats.add("Scanner version changed from " + before.version() + " to " + after.version() + "; detection rules may differ.");
        if (after.timedOut > 0 || after.failed > 0) d.caveats.add("The current scan contains inconclusive TCP attempts. Missing services may still be reachable.");
        return d;
    }
    private static List<Integer> extras(List<Integer> ports) { return ports == null ? List.of() : ports; }
    private static Map<String,ScanReport.Finding> findings(ScanReport r) { Map<String,ScanReport.Finding> m = new java.util.LinkedHashMap<>(); for (ScanReport.Finding f : r.findings) m.put(f.port + "\n" + f.title,f); return m; }
    private static Set<Integer> openPorts(ScanReport r) { Set<Integer> ports = new HashSet<>(); for (ScanReport.Port p : r.ports) ports.add(p.number); return ports; }
    public String summary() { return newFindings + " newly observed · " + missingFindings + " not observed again · " + retainedFindings + " retained · " + changedFindings + " changed"; }
}
