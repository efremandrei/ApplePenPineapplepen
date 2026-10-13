package info.hen14.applepen.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Small bounded JSON reader for NVD responses; rejects malformed or oversized input. */
public final class JsonReader {
    private final String input;
    private int at;
    private JsonReader(String input) { if (input.length() > 1048576) throw new IllegalArgumentException("JSON exceeds 1 MiB"); this.input = input; }
    public static Object parse(String input) { JsonReader reader = new JsonReader(input); Object value = reader.value(0); reader.space(); if (reader.at != input.length()) throw reader.error(); return value; }
    private IllegalArgumentException error() { return new IllegalArgumentException("Invalid JSON at character " + at); }
    private void space() { while (at < input.length() && " \r\n\t".indexOf(input.charAt(at)) >= 0) at++; }
    private boolean take(char c) { space(); if (at < input.length() && input.charAt(at) == c) { at++; return true; } return false; }
    private Object value(int depth) {
        if (depth > 64) throw new IllegalArgumentException("JSON nesting exceeds 64 levels");
        space(); if (at >= input.length()) throw error(); char c = input.charAt(at);
        if (c == '"') return string();
        if (take('{')) {
            Map<String,Object> map = new LinkedHashMap<>(); if (take('}')) return map;
            do { space(); if (at >= input.length() || input.charAt(at) != '"') throw error(); String key = string(); if (!take(':') || map.containsKey(key)) throw error(); map.put(key,value(depth+1)); } while (take(','));
            if (!take('}')) throw error(); return map;
        }
        if (take('[')) { List<Object> list = new ArrayList<>(); if (take(']')) return list; do { list.add(value(depth+1)); } while (take(',')); if (!take(']')) throw error(); return list; }
        for (String literal : new String[]{"true","false","null"}) if (input.startsWith(literal,at)) { at += literal.length(); return literal.equals("null") ? null : Boolean.valueOf(literal); }
        int start = at;
        while (at < input.length() && "-+0123456789.eE".indexOf(input.charAt(at)) >= 0) at++;
        String number = input.substring(start,at);
        if (number.length() > 64 || !number.matches("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")) throw error();
        try { return new java.math.BigDecimal(number); } catch (NumberFormatException e) { throw error(); }
    }
    private String string() {
        at++; StringBuilder b = new StringBuilder();
        while (at < input.length()) {
            char c = input.charAt(at++); if (c == '"') return b.toString(); if (c < 32) throw error();
            if (c != '\\') { b.append(c); continue; }
            if (at >= input.length()) throw error(); char escape = input.charAt(at++);
            switch (escape) {
                case '"', '\\', '/' -> b.append(escape);
                case 'b' -> b.append('\b'); case 'f' -> b.append('\f'); case 'n' -> b.append('\n'); case 'r' -> b.append('\r'); case 't' -> b.append('\t');
                case 'u' -> { if (at+4 > input.length()) throw error(); String hex = input.substring(at,at+4); if (!hex.matches("[0-9a-fA-F]{4}")) throw error(); b.append((char)Integer.parseInt(hex,16)); at += 4; }
                default -> throw error();
            }
        }
        throw error();
    }
    @SuppressWarnings("unchecked") public static Map<String,Object> object(Object value) { return value instanceof Map ? (Map<String,Object>)value : Map.of(); }
    public static List<?> array(Object value) { return value instanceof List ? (List<?>)value : List.of(); }
    public static String string(Object value) { return value instanceof String ? (String)value : ""; }
    public static int integer(Object value) { return value instanceof Number ? ((Number)value).intValue() : 0; }
}
