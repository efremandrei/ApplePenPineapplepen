package info.hen14.applepen;

import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.graphics.pdf.PdfDocument;
import info.hen14.applepen.core.ReportExporter;
import info.hen14.applepen.core.ScanReport;
import java.io.OutputStream;

public final class PdfExporter {
    private PdfExporter() { }
    public static void write(ScanReport report, OutputStream output) throws Exception {
        PdfDocument document = new PdfDocument();
        try {
            Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
            paint.setTypeface(Typeface.create("sans-serif", Typeface.NORMAL)); paint.setTextSize(10);
            PdfDocument.Page page = null; Canvas canvas = null;
            int number = 0, y = 0;
            for (String block : ReportExporter.text(report)) {
                for (String rawLine : block.split("\n", -1)) {
                    String remaining = rawLine;
                    do {
                        if (page == null || y > 780) {
                            if (page != null) document.finishPage(page);
                            page = document.startPage(new PdfDocument.PageInfo.Builder(595, 842, ++number).create()); canvas = page.getCanvas();
                            paint.setColor(Color.rgb(0,126,128)); paint.setTextSize(10);
                            canvas.drawText("ApplePen · " + report.config.ip, 40, 30, paint);
                            canvas.drawText("Page " + number, 510, 818, paint);
                            paint.setColor(Color.rgb(20,42,52)); y = 60;
                        }
                        int chars = remaining.isEmpty() ? 0 : paint.breakText(remaining, true, 515, null);
                        if (!remaining.isEmpty() && chars == 0) chars = 1;
                        if (chars < remaining.length() && chars > 0 && Character.isHighSurrogate(remaining.charAt(chars - 1))) chars--;
                        String line = remaining.substring(0, chars);
                        canvas.drawText(line, 40, y, paint); y += 15;
                        remaining = remaining.substring(chars);
                    } while (!remaining.isEmpty());
                }
            }
            if (page != null) document.finishPage(page);
            document.writeTo(output);
        } finally { document.close(); }
    }
}
