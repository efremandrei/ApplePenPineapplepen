package info.hen14.applepen.core;
import java.util.ArrayList;
public interface CveLookup {
    final class Result {
        public final ArrayList<ScanReport.Finding> findings = new ArrayList<>();
        public final ArrayList<String> coverage = new ArrayList<>();
    }
    Result lookup(ProductFingerprint product, int port) throws Exception;
    void cancel();
}
