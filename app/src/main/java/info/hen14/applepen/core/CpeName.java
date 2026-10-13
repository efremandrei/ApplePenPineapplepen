package info.hen14.applepen.core;

import java.util.ArrayList;
import java.util.Locale;

/** Bounded formatted-string binding reader, not a complete CPE name matcher. */
public final class CpeName {
    private final String[] fields;
    private CpeName(String[] fields) { this.fields = fields; }
    public static CpeName parse(String value) {
        if (value == null || value.length() > 2048 || value.matches("(?s).*[\\p{Cntrl}].*")) return null;
        ArrayList<String> parts = new ArrayList<>(); StringBuilder field = new StringBuilder(); boolean escaped = false;
        for (char c : value.toCharArray()) {
            if (escaped) { field.append('\\').append(c); escaped = false; }
            else if (c == '\\') escaped = true;
            else if (c == ':') { parts.add(field.toString()); field.setLength(0); }
            else field.append(c);
        }
        if (escaped) return null; parts.add(field.toString());
        if (parts.size() != 13 || !parts.get(0).equals("cpe") || !parts.get(1).equals("2.3")) return null;
        for (int i=2;i<13;i++) if (parts.get(i).isEmpty() || parts.get(i).length() > 256) return null;
        return new CpeName(parts.toArray(new String[0]));
    }
    public String field(int index) { return fields[index].toLowerCase(Locale.ROOT); }
    public boolean literal(int index) { String f = fields[index]; return !f.equals("*") && !f.equals("-") && f.indexOf('*') < 0 && f.indexOf('?') < 0 && f.indexOf('\\') < 0; }
    public int restrictions() { int count = 0; for(int i=7;i<13;i++) if (!fields[i].equals("*")) count++; return count; }
}
