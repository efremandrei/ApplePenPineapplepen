package info.hen14.applepen.core;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Numeric release ordering for the supported fingerprints; unsupported suffixes stay unknown. */
public final class VersionNumbers {
    private static final Pattern FORMAT = Pattern.compile("([0-9]{1,9}(?:\\.[0-9]{1,9}){1,3})(?:p([0-9]{1,9}))?");
    private final int[] release;
    private final Integer portable;
    private VersionNumbers(int[] release,Integer portable) { this.release=release; this.portable=portable; }
    public static VersionNumbers parse(String value) {
        if(value == null || value.length() > 64) return null;
        Matcher m=FORMAT.matcher(value); if(!m.matches()) return null;
        String[] parts=m.group(1).split("\\."); int[] numbers=new int[parts.length];
        for(int i=0;i<parts.length;i++) { if(parts[i].length()>1 && parts[i].startsWith("0")) return null; numbers[i]=Integer.parseInt(parts[i]); }
        String p=m.group(2); if(p!=null && p.length()>1 && p.startsWith("0")) return null;
        return new VersionNumbers(numbers,p==null ? null : Integer.valueOf(p));
    }
    public String base() { StringBuilder b=new StringBuilder(); for(int n:release) { if(b.length()>0)b.append('.'); b.append(n); } return b.toString(); }
    public boolean hasPortable() { return portable!=null; }
    public static Integer compare(String a,String b) {
        VersionNumbers x=parse(a),y=parse(b); if(x==null || y==null) return null;
        for(int i=0;i<Math.max(x.release.length,y.release.length);i++) { int c=Integer.compare(i<x.release.length ? x.release[i] : 0,i<y.release.length ? y.release[i] : 0); if(c!=0)return c; }
        // A release-only boundary may refer to upstream or portable builds; do not guess.
        if((x.portable==null)!=(y.portable==null)) return null;
        return x.portable==null ? 0 : Integer.compare(x.portable,y.portable);
    }
}
