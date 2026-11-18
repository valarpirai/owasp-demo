package com.owasp.demo.util;

import java.util.List;
import java.util.Map;

/**
 * Looks up values in a parsed YAML tree by dotted path, such as "session.timeout_minutes".
 */
public final class ConfigUtil {

    private ConfigUtil() {}

    /**
     * Walks the tree one key at a time.
     *
     * @param root parsed YAML map
     * @param path dotted key path
     * @return the value at the path
     * @throws IllegalStateException if any key on the path is missing
     */
    @SuppressWarnings("unchecked")
    public static Object lookup(Map<String, Object> root, String path) {
        Object node = root;
        for (String key : path.split("\\.")) {
            if (!(node instanceof Map) || !((Map<String, Object>) node).containsKey(key)) {
                throw new IllegalStateException("Missing config key: " + path);
            }
            node = ((Map<String, Object>) node).get(key);
        }
        return node;
    }

    /**
     * @param root parsed YAML map
     * @param path dotted key path
     * @return the value as a string
     */
    public static String getString(Map<String, Object> root, String path) {
        return String.valueOf(lookup(root, path));
    }

    /**
     * @param root parsed YAML map
     * @param path dotted key path
     * @return the value as an int
     */
    public static int getInt(Map<String, Object> root, String path) {
        return ((Number) lookup(root, path)).intValue();
    }

    /**
     * @param root parsed YAML map
     * @param path dotted key path
     * @return the value as a list of strings
     */
    @SuppressWarnings("unchecked")
    public static List<String> getStringList(Map<String, Object> root, String path) {
        return ((List<Object>) lookup(root, path)).stream().map(String::valueOf).toList();
    }

    /**
     * @param root parsed YAML map
     * @param path dotted key path
     * @return the value as a string map
     */
    @SuppressWarnings("unchecked")
    public static Map<String, String> getStringMap(Map<String, Object> root, String path) {
        Map<String, Object> raw = (Map<String, Object>) lookup(root, path);
        Map<String, String> out = new java.util.LinkedHashMap<>();
        raw.forEach((k, v) -> out.put(k, String.valueOf(v)));
        return out;
    }
}
