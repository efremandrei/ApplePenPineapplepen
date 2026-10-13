package info.hen14.applepen;

import android.content.Context;
import android.util.AtomicFile;
import info.hen14.applepen.core.ScanReport;
import java.io.File;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

/** Reports stay in private application storage. No external report deserialization. */
public final class ReportStore {
    private final File directory;
    public ReportStore(Context context) { directory = new File(context.getFilesDir(), "reports"); if (!directory.exists() && !directory.mkdirs()) throw new IllegalStateException("Cannot create report storage"); }
    public synchronized void save(ScanReport report) throws Exception {
        AtomicFile file = new AtomicFile(new File(directory, report.id + ".report"));
        FileOutputStream stream = file.startWrite();
        try { ObjectOutputStream output = new ObjectOutputStream(stream); output.writeObject(report); output.flush(); file.finishWrite(stream); }
        catch (Exception e) { file.failWrite(stream); throw e; }
        File[] files = files();
        for (int i = 30; i < files.length; i++) new AtomicFile(files[i]).delete();
    }
    private File[] files() {
        File[] files = directory.listFiles((folder, name) -> name.endsWith(".report"));
        if (files == null) return new File[0];
        Arrays.sort(files, Comparator.comparingLong(File::lastModified).reversed()); return files;
    }
    public synchronized List<ScanReport> list() {
        List<ScanReport> reports = new ArrayList<>();
        for (File file : files()) { ScanReport r = loadFile(file); if (r != null) reports.add(r); }
        reports.sort(Comparator.comparingLong((ScanReport r) -> r.startedAt).reversed()); return reports;
    }
    private ScanReport loadFile(File file) {
        try (ObjectInputStream input = new ObjectInputStream(new AtomicFile(file).openRead())) { return (ScanReport) input.readObject(); }
        catch (Exception ignored) { return null; }
    }
    public synchronized ScanReport load(String id) { if (id == null || !id.matches("[a-f0-9-]{36}")) return null; return loadFile(new File(directory, id + ".report")); }
    public synchronized void delete(String id) { if (id != null && id.matches("[a-f0-9-]{36}")) new AtomicFile(new File(directory, id + ".report")).delete(); }
}
