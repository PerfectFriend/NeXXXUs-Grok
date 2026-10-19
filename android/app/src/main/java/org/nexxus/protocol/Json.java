package org.nexxus.protocol;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Flat-enough JSON for hello, chat and our own state files. */
public final class Json {
    private Json() {}

    public static String stringify(Object value) {
        StringBuilder sb = new StringBuilder();
        write(sb, value);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> obj(String json) {
        Object v = parse(json);
        if (!(v instanceof Map)) throw new IllegalArgumentException("ожидался объект");
        return (Map<String, Object>) v;
    }

    public static Object parse(String json) {
        return new Parser(json).parseValue();
    }

    public static String str(Map<String, Object> o, String k) {
        Object v = o.get(k);
        if (v == null) return "";
        return String.valueOf(v);
    }

    public static int num(Map<String, Object> o, String k) {
        Object v = o.get(k);
        if (v == null) return 0;
        if (v instanceof Number) return ((Number) v).intValue();
        return Integer.parseInt(String.valueOf(v));
    }

    private static void write(StringBuilder sb, Object value) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof String) {
            sb.append('"');
            String s = (String) value;
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                switch (c) {
                    case '"': sb.append("\\\""); break;
                    case '\\': sb.append("\\\\"); break;
                    case '\b': sb.append("\\b"); break;
                    case '\f': sb.append("\\f"); break;
                    case '\n': sb.append("\\n"); break;
                    case '\r': sb.append("\\r"); break;
                    case '\t': sb.append("\\t"); break;
                    default:
                        if (c < 0x20) {
                            sb.append(String.format("\\u%04x", (int) c));
                        } else {
                            sb.append(c);
                        }
                }
            }
            sb.append('"');
        } else if (value instanceof Number || value instanceof Boolean) {
            sb.append(value.toString());
        } else if (value instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) value).entrySet()) {
                if (!first) sb.append(',');
                first = false;
                write(sb, String.valueOf(e.getKey()));
                sb.append(':');
                write(sb, e.getValue());
            }
            sb.append('}');
        } else if (value instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object item : (List<?>) value) {
                if (!first) sb.append(',');
                first = false;
                write(sb, item);
            }
            sb.append(']');
        } else {
            throw new IllegalArgumentException("json " + value.getClass());
        }
    }

    private static final class Parser {
        private final String s;
        private int i;

        Parser(String s) { this.s = s; }

        Object parseValue() {
            skip();
            Object v = value();
            skip();
            if (i != s.length()) throw new IllegalArgumentException("хвост json");
            return v;
        }

        private Object value() {
            skip();
            if (i >= s.length()) throw new IllegalArgumentException("пустой json");
            char c = s.charAt(i);
            if (c == '{') return object();
            if (c == '[') return array();
            if (c == '"') return string();
            if (c == 't') { expect("true"); return Boolean.TRUE; }
            if (c == 'f') { expect("false"); return Boolean.FALSE; }
            if (c == 'n') { expect("null"); return null; }
            return number();
        }

        private Map<String, Object> object() {
            expect("{");
            Map<String, Object> map = new LinkedHashMap<String, Object>();
            skip();
            if (peek('}')) { i++; return map; }
            while (true) {
                skip();
                String key = string();
                skip();
                expect(":");
                Object val = value();
                map.put(key, val);
                skip();
                if (peek('}')) { i++; return map; }
                expect(",");
            }
        }

        private List<Object> array() {
            expect("[");
            List<Object> list = new ArrayList<Object>();
            skip();
            if (peek(']')) { i++; return list; }
            while (true) {
                list.add(value());
                skip();
                if (peek(']')) { i++; return list; }
                expect(",");
            }
        }

        private String string() {
            expect("\"");
            StringBuilder sb = new StringBuilder();
            while (i < s.length()) {
                char c = s.charAt(i++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    if (i >= s.length()) break;
                    char e = s.charAt(i++);
                    switch (e) {
                        case '"':
                        case '\\':
                        case '/': sb.append(e); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            if (i + 4 > s.length()) throw new IllegalArgumentException("\\u");
                            int cp = Integer.parseInt(s.substring(i, i + 4), 16);
                            sb.append((char) cp);
                            i += 4;
                            break;
                        default: throw new IllegalArgumentException("escape");
                    }
                } else {
                    sb.append(c);
                }
            }
            throw new IllegalArgumentException("строка не закрыта");
        }

        private Number number() {
            int start = i;
            if (peek('-')) i++;
            while (i < s.length()) {
                char c = s.charAt(i);
                if ((c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') i++;
                else break;
            }
            String raw = s.substring(start, i);
            if (raw.indexOf('.') >= 0 || raw.indexOf('e') >= 0 || raw.indexOf('E') >= 0) {
                return Double.valueOf(raw);
            }
            return Long.valueOf(raw);
        }

        private void skip() {
            while (i < s.length()) {
                char c = s.charAt(i);
                if (c == ' ' || c == '\n' || c == '\r' || c == '\t') i++;
                else break;
            }
        }

        private boolean peek(char c) {
            return i < s.length() && s.charAt(i) == c;
        }

        private void expect(String lit) {
            skip();
            if (!s.startsWith(lit, i)) throw new IllegalArgumentException("ожидалось " + lit);
            i += lit.length();
        }
    }
}
