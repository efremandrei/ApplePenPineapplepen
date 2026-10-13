package info.hen14.applepen;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.WindowInsets;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;
import info.hen14.applepen.core.ReportExporter;
import info.hen14.applepen.core.ScanConfig;
import info.hen14.applepen.core.ScanReport;
import info.hen14.applepen.core.AppVersion;
import info.hen14.applepen.core.ReportDiff;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private static final int TEAL = Color.rgb(0,126,128), INK = Color.rgb(20,42,52), MUTED = Color.rgb(82,102,110), BG = Color.rgb(245,247,248);
    private static final String[] PROFILES = {"Quick · common ports", "Standard · 1–1024 + common", "Full TCP · 1–65535", "Custom ports"};
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private LinearLayout root, content, progressCard;
    private TextView progressText, progressCount;
    private ProgressBar progressBar;
    private EditText ipInput, hostnameInput, portsInput, timeoutInput, concurrencyInput, httpPortsInput, httpsPortsInput;
    private CheckBox authorized, cveLookupInput;
    private Spinner profile;
    private Button startButton;
    private ReportStore store;
    private String ip = "", hostname = "", ports = ScanConfig.QUICK_PORTS, timeout = "800", concurrency = "12", tab = "Scan";
    private int profileIndex;
    private String extraHttp = "", extraHttps = "", findingFilter = "All";
    private boolean lookupCves;
    private ScanReport selected, pendingExport;
    private String exportFormat = "", lastFinishedId = "";
    private boolean wasRunning;
    private ScanConfig waitingConfig;
    private final Runnable poll = new Runnable() {
        @Override public void run() {
            ScanService.State state = ScanService.state;
            if (progressText != null) {
                progressText.setText(state.running ? state.message : "Ready for a new assessment");
                progressCount.setText(state.running ? state.completed + " / " + state.total + " ports processed" : "One target · no root required");
                progressBar.setMax(Math.max(1,state.total)); progressBar.setProgress(state.completed);
                progressBar.setIndeterminate(state.running && state.completed == state.total);
                progressBar.setVisibility(state.running ? View.VISIBLE : View.GONE);
                startButton.setText(state.running ? "Stop scan" : "Start assessment");
                setInputsEnabled(!state.running);
            }
            if (state.report != null && !state.report.id.equals(lastFinishedId)) {
                lastFinishedId = state.report.id; selected = state.report;
                if (wasRunning || getIntent().getBooleanExtra("showReport", false)) { rememberForm(); tab = "Report"; render(); }
                if (!state.persistenceError.isEmpty()) toast(state.persistenceError);
            }
            wasRunning = state.running;
            handler.postDelayed(this, 500);
        }
    };
    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved); store = new ReportStore(this);
        SharedPreferences prefs = getPreferences(MODE_PRIVATE);
        ip = prefs.getString("ip", ""); hostname = prefs.getString("hostname", "");
        ports = prefs.getString("ports", ScanConfig.QUICK_PORTS); profileIndex = prefs.getInt("profile", 0);
        timeout = prefs.getString("timeout", "800"); concurrency = prefs.getString("concurrency", "12");
        extraHttp = prefs.getString("extraHttp", ""); extraHttps = prefs.getString("extraHttps", ""); lookupCves = prefs.getBoolean("lookupCves", false);
        if (saved != null) {
            ip = saved.getString("ip",ip); hostname = saved.getString("hostname",hostname); ports = saved.getString("ports",ports);
            timeout = saved.getString("timeout",timeout); concurrency = saved.getString("concurrency",concurrency);
            profileIndex = saved.getInt("profile",profileIndex); tab = saved.getString("tab","Scan");
            selected = store.load(saved.getString("report")); pendingExport = store.load(saved.getString("exportReport"));
            exportFormat = saved.getString("exportFormat", ""); lastFinishedId = saved.getString("lastFinishedId", "");
            extraHttp = saved.getString("extraHttp",extraHttp); extraHttps = saved.getString("extraHttps",extraHttps); lookupCves = saved.getBoolean("lookupCves",lookupCves);
            if (Build.VERSION.SDK_INT >= 33) waitingConfig = saved.getSerializable("waitingConfig",ScanConfig.class); else waitingConfig = (ScanConfig)saved.getSerializable("waitingConfig");
        }
        wasRunning = ScanService.state.running;
        render();
    }
    @Override protected void onResume() { super.onResume(); handler.removeCallbacks(poll); handler.post(poll); }
    @Override protected void onPause() { handler.removeCallbacks(poll); super.onPause(); }
    @Override protected void onDestroy() { handler.removeCallbacks(poll); io.shutdown(); super.onDestroy(); }
    @Override public void onSaveInstanceState(Bundle out) {
        rememberForm(); out.putString("ip",ip); out.putString("hostname",hostname); out.putString("ports",ports);
        out.putString("timeout",timeout); out.putString("concurrency",concurrency); out.putInt("profile",profileIndex);
        out.putString("tab",tab); out.putString("report",selected == null ? null : selected.id);
        out.putString("exportReport",pendingExport == null ? null : pendingExport.id); out.putString("exportFormat",exportFormat);
        out.putString("lastFinishedId",lastFinishedId); super.onSaveInstanceState(out);
        out.putString("extraHttp",extraHttp); out.putString("extraHttps",extraHttps); out.putBoolean("lookupCves",lookupCves); out.putSerializable("waitingConfig",waitingConfig);
    }
    private int dp(int value) { return Math.round(getResources().getDisplayMetrics().density * value); }
    private LinearLayout column() { LinearLayout v = new LinearLayout(this); v.setOrientation(LinearLayout.VERTICAL); return v; }
    private LinearLayout row() { LinearLayout v = new LinearLayout(this); v.setOrientation(LinearLayout.HORIZONTAL); v.setGravity(Gravity.CENTER_VERTICAL); return v; }
    private TextView text(String value, int size, int color, boolean bold) {
        TextView t = new TextView(this); t.setText(value); t.setTextSize(size); t.setTextColor(color);
        t.setLineSpacing(dp(3),1); if (bold) t.setTypeface(Typeface.DEFAULT,Typeface.BOLD); t.setPadding(0,dp(4),0,dp(4)); return t;
    }
    private GradientDrawable background(int color, int radius) { GradientDrawable d = new GradientDrawable(); d.setColor(color); d.setCornerRadius(dp(radius)); return d; }
    private LinearLayout card() {
        LinearLayout v = column(); v.setPadding(dp(18),dp(14),dp(18),dp(14)); v.setBackground(background(Color.WHITE,18));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1,-2); params.bottomMargin = dp(14); v.setLayoutParams(params); return v;
    }
    private Button button(String label, boolean primary, Runnable action) {
        Button b = new Button(this); b.setText(label); b.setAllCaps(false); b.setTextSize(14);
        b.setTextColor(primary ? Color.WHITE : TEAL); b.setBackground(background(primary ? TEAL : Color.rgb(224,240,240),12));
        b.setPadding(dp(14),dp(10),dp(14),dp(10)); b.setMinHeight(dp(48));
        b.setOnClickListener(view -> action.run()); return b;
    }
    private void render() {
        ipInput = null; progressText = null;
        root = column(); root.setBackgroundColor(BG);
        root.setOnApplyWindowInsetsListener((view,insets) -> {
            android.graphics.Insets bars = insets.getInsets(WindowInsets.Type.systemBars());
            root.setPadding(bars.left,bars.top,bars.right,bars.bottom); return insets;
        });
        LinearLayout top = column(); top.setPadding(dp(22),dp(14),dp(22),dp(10));
        top.addView(text("APPLEPEN",28,INK,true)); top.addView(text("Network security, from your phone · " + AppVersion.VERSION,13,MUTED,false)); root.addView(top);
        LinearLayout tabs = row(); tabs.setPadding(dp(16),0,dp(16),dp(12));
        for (String name : new String[]{"Scan","History","Report"}) {
            Button b = button(name,tab.equals(name),() -> { rememberForm(); tab = name; render(); });
            LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(0,dp(46),1); p.setMargins(dp(4),0,dp(4),0); tabs.addView(b,p);
        }
        root.addView(tabs); ScrollView scroll = new ScrollView(this); scroll.setFillViewport(true);
        content = column(); content.setPadding(dp(20),dp(4),dp(20),dp(24)); scroll.addView(content); root.addView(scroll,new LinearLayout.LayoutParams(-1,0,1));
        if (tab.equals("Scan")) renderScan(); else if (tab.equals("History")) renderHistory(); else renderReport();
        setContentView(root); root.requestApplyInsets();
    }
    private EditText field(LinearLayout card, String label, String hint, String value, boolean numeric) {
        card.addView(text(label,13,MUTED,true)); EditText field = new EditText(this); field.setTextSize(16);
        field.setSingleLine(true); field.setHint(hint); field.setText(value);
        field.setContentDescription(label);
        field.setInputType(numeric ? InputType.TYPE_CLASS_NUMBER : InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        card.addView(field,new LinearLayout.LayoutParams(-1,dp(52))); return field;
    }
    private void renderScan() {
        progressCard = card(); progressText = text(ScanService.state.running ? ScanService.state.message : "Ready for a new assessment",18,INK,true);
        progressCount = text("One target · no root required",13,MUTED,false); progressBar = new ProgressBar(this,null,android.R.attr.progressBarStyleHorizontal);
        progressCard.addView(progressText); progressCard.addView(progressCount); progressCard.addView(progressBar); content.addView(progressCard);
        LinearLayout target = card(); target.addView(text("01  Target",18,INK,true));
        ipInput = field(target,"Destination IP","192.168.1.10 or IPv6",ip,false);
        hostnameInput = field(target,"Hostname · optional","server.example.com",hostname,false);
        target.addView(text("Connections go only to the IP. The hostname selects the web site and certificate identity.",12,MUTED,false)); content.addView(target);
        LinearLayout checks = card(); checks.addView(text("02  Scan settings",18,INK,true));
        profile = new Spinner(this); profile.setAdapter(new ArrayAdapter<>(this,android.R.layout.simple_spinner_dropdown_item,PROFILES)); profile.setSelection(profileIndex); checks.addView(profile);
        portsInput = field(checks,"TCP ports","22,80,443 or 1-1024",ports,false);
        timeoutInput = field(checks,"Connection timeout · milliseconds","800",timeout,true);
        concurrencyInput = field(checks,"Parallel connections · 1–24","12",concurrency,true);
        profile.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                profileIndex = position;
                if (position == 0) portsInput.setText(ScanConfig.QUICK_PORTS);
                if (position == 1) portsInput.setText("1-1024," + ScanConfig.QUICK_PORTS);
                if (position == 2) portsInput.setText("1-65535");
                portsInput.setEnabled(position == 3 && !ScanService.state.running);
            }
            @Override public void onNothingSelected(AdapterView<?> parent) { }
        });
        checks.addView(text("Full scans can take several minutes. A 20-minute limit produces a partial report if necessary.",12,MUTED,false)); content.addView(checks);
        LinearLayout additional = card(); additional.addView(text("Additional web checks",18,INK,true));
        httpPortsInput = field(additional,"Additional HTTP ports","8089,10080",extraHttp,false);
        httpsPortsInput = field(additional,"Additional HTTPS ports","9443,10443",extraHttps,false);
        additional.addView(text("Include these ports in the TCP selection above. HTTP checks send one root request; other ports receive greeting checks only.",12,MUTED,false));
        cveLookupInput = new CheckBox(this); cveLookupInput.setText("Look up detected versions in NVD"); cveLookupInput.setChecked(lookupCves); cveLookupInput.setTextColor(INK); additional.addView(cveLookupInput);
        additional.addView(text("Optional online lookup sends product/version data to NVD, without your target IP or hostname. Results are potential CVEs; patch status remains unverified. Internet access is needed for uncached results.",12,MUTED,false)); content.addView(additional);
        LinearLayout scope = card(); scope.addView(text("03  Assessment scope",18,INK,true));
        scope.addView(text("TCP discovery · service banners · HTTP configuration · TLS certificates. No credential guessing or exploit execution. Coverage is recorded in every report.",14,MUTED,false));
        authorized = new CheckBox(this); authorized.setText("I own this target or have permission to assess it."); authorized.setTextColor(INK); scope.addView(authorized); content.addView(scope);
        startButton = button(ScanService.state.running ? "Stop scan" : "Start assessment",true,this::startOrStop); content.addView(startButton,new LinearLayout.LayoutParams(-1,dp(54)));
        content.addView(text("Reports stay on this device. Export only when you choose.",12,MUTED,false));
    }
    private void setInputsEnabled(boolean enabled) {
        if (ipInput == null) return;
        ipInput.setEnabled(enabled); hostnameInput.setEnabled(enabled); timeoutInput.setEnabled(enabled);
        concurrencyInput.setEnabled(enabled); profile.setEnabled(enabled); portsInput.setEnabled(enabled && profileIndex == 3); authorized.setEnabled(enabled);
        httpPortsInput.setEnabled(enabled); httpsPortsInput.setEnabled(enabled); cveLookupInput.setEnabled(enabled);
    }
    private void rememberForm() {
        if (ipInput == null) return;
        ip = ipInput.getText().toString(); hostname = hostnameInput.getText().toString(); ports = portsInput.getText().toString();
        timeout = timeoutInput.getText().toString(); concurrency = concurrencyInput.getText().toString();
        extraHttp = httpPortsInput.getText().toString(); extraHttps = httpsPortsInput.getText().toString(); lookupCves = cveLookupInput.isChecked();
    }
    private void startOrStop() {
        if (ScanService.state.running) { startService(new Intent(this,ScanService.class).setAction(ScanService.CANCEL)); return; }
        rememberForm();
        if (!authorized.isChecked()) { toast("Confirm permission for this target before starting."); return; }
        try {
            waitingConfig = new ScanConfig(ip,hostname,PROFILES[profileIndex],ports,Integer.parseInt(timeout),Integer.parseInt(concurrency),extraHttp,extraHttps,lookupCves);
            getPreferences(MODE_PRIVATE).edit().putString("ip",ip).putString("hostname",hostname).putString("ports",ports).putInt("profile",profileIndex).putString("timeout",timeout).putString("concurrency",concurrency).apply();
            getPreferences(MODE_PRIVATE).edit().putString("extraHttp",extraHttp).putString("extraHttps",extraHttps).putBoolean("lookupCves",lookupCves).apply();
            if (Build.VERSION.SDK_INT >= 37 && getApplicationInfo().targetSdkVersion >= 37 && checkSelfPermission("android.permission.ACCESS_LOCAL_NETWORK") != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{"android.permission.ACCESS_LOCAL_NETWORK"},102); return;
            }
            requestNotificationAndStart();
        } catch (NumberFormatException e) { toast("Timeout and connection count must be numbers."); }
        catch (IllegalArgumentException e) { toast(e.getMessage()); }
    }
    private void requestNotificationAndStart() {
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS},101);
        else launchScan();
    }
    private void launchScan() {
        if (waitingConfig == null) return;
        try { startForegroundService(new Intent(this,ScanService.class).setAction(ScanService.START).putExtra("config",waitingConfig)); wasRunning = true; waitingConfig = null; }
        catch (Exception e) { toast("Could not start scan: " + e.getMessage()); }
    }
    @Override public void onRequestPermissionsResult(int request, String[] permissions, int[] grants) {
        super.onRequestPermissionsResult(request,permissions,grants);
        if (request == 101) launchScan();
        if (request == 102) {
            if (grants.length > 0 && grants[0] == PackageManager.PERMISSION_GRANTED) requestNotificationAndStart();
            else toast("Local-network permission is needed for LAN assessment.");
        }
    }
    private void renderHistory() {
        content.addView(text("Saved assessments",22,INK,true)); content.addView(text("The 30 most recent reports are kept on this device.",13,MUTED,false));
        List<ScanReport> reports = store.list();
        if (reports.isEmpty()) { LinearLayout empty = card(); empty.addView(text("Your reports will appear here",18,INK,true)); empty.addView(text("Start a scan to record services, findings, and coverage.",14,MUTED,false)); content.addView(empty); }
        for (ScanReport report : reports) {
            if (report.status.equals("Running") && !ScanService.state.running) {
                report.status = "Interrupted"; report.finishedAt = System.currentTimeMillis();
                report.coverage.add("The process ended before completion. No complete result was saved.");
                try { store.save(report); } catch (Exception ignored) { }
            }
            LinearLayout c = card(); c.addView(text(report.config.ip,19,INK,true)); c.addView(text(ReportExporter.date(report.startedAt),12,MUTED,false)); c.addView(text(report.summary(),14,TEAL,true));
            if (report.status.equals("Running")) { c.addView(text("The assessment is still running.",13,MUTED,false)); }
            else {
                c.addView(button("Open report",true,() -> { selected = report; tab = "Report"; render(); }));
                c.addView(button("Rescan this target",false,() -> rescan(report)));
                c.addView(button("Delete",false,() -> new AlertDialog.Builder(this).setTitle("Delete this report?").setMessage("Exported copies are kept.").setNegativeButton("Cancel",null).setPositiveButton("Delete",(dialog,which) -> { store.delete(report.id); if (selected != null && selected.id.equals(report.id)) selected = null; render(); }).show()));
            }
            content.addView(c);
        }
    }
    private int severityColor(String severity) { return switch(severity) { case "Critical", "High" -> Color.rgb(180,45,53); case "Medium" -> Color.rgb(167,92,12); case "Low" -> Color.rgb(36,109,147); default -> TEAL; }; }
    private void renderReport() {
        if (selected == null) selected = ScanService.state.report;
        if (selected == null) {
            LinearLayout empty = card(); empty.addView(text("No report selected",20,INK,true)); empty.addView(text("Complete a scan or open one from History.",14,MUTED,false)); content.addView(empty); return;
        }
        ScanReport r = selected;
        LinearLayout summary = card(); summary.addView(text(r.config.ip,24,INK,true)); summary.addView(text(r.summary(),15,TEAL,true));
        summary.addView(text(ReportExporter.date(r.startedAt) + "\n" + r.network,12,MUTED,false));
        summary.addView(text("Critical " + r.count("Critical") + "   High " + r.count("High") + "   Medium " + r.count("Medium") + "   Low " + r.count("Low") + "   Info " + r.count("Info"),13,INK,true));
        summary.addView(text("Processed " + r.attempted + "/" + r.config.ports.size() + " ports · " + r.timedOut + " timeouts · " + r.failed + " errors",13,MUTED,false));
        if (!r.error.isEmpty()) summary.addView(text(r.error,14,severityColor("High"),false));
        LinearLayout exports = row();
        for (String format : new String[]{"PDF","HTML","JSON"}) { Button b = button(format,false,() -> export(format)); LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(0,dp(48),1); p.setMargins(dp(3),dp(6),dp(3),0); exports.addView(b,p); }
        summary.addView(exports); summary.addView(button("Compare with an earlier scan",false,() -> chooseComparison(r))); content.addView(summary);
        if (r.comparison != null) {
            LinearLayout diff = card(); diff.addView(text("Changes since " + ReportExporter.date(r.comparison.baselineStartedAt),17,INK,true)); diff.addView(text(r.comparison.summary(),14,TEAL,true));
            int shown = 0; for (String line : r.comparison.changes) { if (shown++ >= 100) { diff.addView(text("Export for the complete comparison.",13,MUTED,false)); break; } diff.addView(text("• " + line,13,INK,false)); }
            for (String line : r.comparison.caveats) diff.addView(text(line,12,MUTED,false)); content.addView(diff);
        }
        content.addView(text("Findings",21,INK,true));
        LinearLayout filters = row();
        for (String filter : new String[]{"All","High/critical","Potential CVEs"}) { Button b = button(filter,findingFilter.equals(filter),() -> { findingFilter = filter; render(); }); LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(0,dp(54),1); p.setMargins(dp(3),0,dp(3),dp(12)); filters.addView(b,p); }
        content.addView(filters);
        if (r.findings.isEmpty()) content.addView(text("No findings from completed checks. This does not establish that the target is secure.",14,MUTED,false));
        int shownFindings = 0;
        for (ScanReport.Finding f : r.findings) {
            if (findingFilter.equals("High/critical") && !f.severity.equals("High") && !f.severity.equals("Critical")) continue;
            if (findingFilter.equals("Potential CVEs") && !f.status.equals("Potential CVE")) continue;
            if (shownFindings++ >= 200) { content.addView(text("Showing the first 200 findings. Export the report for the complete list.",14,MUTED,false)); break; }
            LinearLayout c = card(); c.addView(text(f.severity.toUpperCase(java.util.Locale.ROOT) + " · TCP " + f.port,12,severityColor(f.severity),true));
            c.addView(text(f.title,18,INK,true)); c.addView(text(f.status + " · " + f.confidence + " confidence",12,MUTED,false));
            TextView evidence = text("Evidence\n" + f.evidence,13,INK,false); evidence.setTextIsSelectable(true); c.addView(evidence);
            c.addView(text("Impact\n" + f.impact,14,MUTED,false)); c.addView(text("Remediation\n" + f.remediation,14,INK,false)); content.addView(c);
            if (f.reference.startsWith("https://")) c.addView(button("Open reference",false,() -> { try { startActivity(new Intent(Intent.ACTION_VIEW,Uri.parse(f.reference))); } catch (Exception e) { toast("No browser available."); } }));
        }
        if (!r.findings.isEmpty() && shownFindings == 0) content.addView(text("No findings match this filter.",14,MUTED,false));
        content.addView(text("Open services",21,INK,true));
        int shownPorts = 0;
        for (ScanReport.Port p : r.ports) {
            if (shownPorts++ >= 200) { content.addView(text("Showing the first 200 services. Export the report for the complete list.",14,MUTED,false)); break; }
            LinearLayout c = card(); c.addView(text("TCP " + p.number + " · " + p.service,16,INK,true)); TextView evidence = text(p.evidence,13,MUTED,false); evidence.setTextIsSelectable(true); c.addView(evidence); content.addView(c);
        }
        LinearLayout coverage = card(); coverage.addView(text("Coverage and limitations",18,INK,true));
        for (String line : r.coverage) coverage.addView(text("• " + line,13,MUTED,false)); content.addView(coverage);
    }
    private void rescan(ScanReport report) {
        ScanConfig c = report.config; ip = c.ip; hostname = c.hostname; ports = joinPorts(c.ports); profileIndex = 3;
        timeout = String.valueOf(c.timeoutMs); concurrency = String.valueOf(c.concurrency); extraHttp = joinPorts(c.extraHttpPorts); extraHttps = joinPorts(c.extraHttpsPorts); lookupCves = c.lookupCves;
        tab = "Scan"; render();
    }
    private String joinPorts(List<Integer> values) {
        if (values == null || values.isEmpty()) return "";
        // Preserve contiguous ranges so a full-scan rescan does not populate a huge input field.
        StringBuilder b = new StringBuilder(); int start = values.get(0), end = start;
        for (int i=1;i<=values.size();i++) { if (i<values.size() && values.get(i)==end+1) { end=values.get(i); continue; } if (b.length()>0) b.append(','); b.append(start); if (end>start) b.append('-').append(end); if (i<values.size()) start=end=values.get(i); }
        return b.toString();
    }
    private void chooseComparison(ScanReport current) {
        java.util.ArrayList<ScanReport> choices = new java.util.ArrayList<>();
        for (ScanReport candidate : store.list()) if (candidate.startedAt < current.startedAt && candidate.config.ip.equals(current.config.ip) && candidate.config.hostname.equals(current.config.hostname)) choices.add(candidate);
        if (choices.isEmpty()) { toast("No earlier report exists for this IP and hostname. Rescan from History to create a comparable report."); return; }
        String[] names = new String[choices.size()]; for (int i=0;i<names.length;i++) names[i] = ReportExporter.date(choices.get(i).startedAt) + " · " + choices.get(i).status;
        new AlertDialog.Builder(this).setTitle("Choose an earlier scan").setItems(names,(dialog,which) -> {
            try { ReportDiff diff = ReportDiff.compare(choices.get(which),current); current.comparison = diff; store.save(current); render(); }
            catch (Exception e) { toast(e.getMessage()); }
        }).setNegativeButton("Cancel",null).show();
    }
    private void export(String format) {
        pendingExport = selected; exportFormat = format;
        String extension = format.toLowerCase(java.util.Locale.ROOT);
        String mime = format.equals("PDF") ? "application/pdf" : format.equals("HTML") ? "text/html" : "application/json";
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType(mime)
            .putExtra(Intent.EXTRA_TITLE,"ApplePen-" + selected.config.ip.replaceAll("[^A-Za-z0-9.-]","_") + "-" + selected.id.substring(0,8) + "." + extension);
        try { startActivityForResult(intent,201); } catch (Exception e) { toast("No document provider is available: " + e.getMessage()); }
    }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request,result,data);
        if (request != 201 || result != RESULT_OK || data == null || data.getData() == null || pendingExport == null) return;
        Uri uri = data.getData(); ScanReport report = pendingExport; String format = exportFormat;
        io.execute(() -> {
            try (OutputStream output = getContentResolver().openOutputStream(uri,"wt")) {
                if (output == null) throw new IllegalStateException("Cannot open destination");
                if (format.equals("PDF")) PdfExporter.write(report,output);
                else output.write((format.equals("HTML") ? ReportExporter.html(report) : ReportExporter.json(report)).getBytes(StandardCharsets.UTF_8));
                runOnUiThread(() -> toast(format + " report saved"));
            } catch (Exception e) { runOnUiThread(() -> toast("Export failed: " + e.getMessage())); }
        });
    }
    private void toast(String message) { Toast.makeText(this,message,Toast.LENGTH_LONG).show(); }
}
