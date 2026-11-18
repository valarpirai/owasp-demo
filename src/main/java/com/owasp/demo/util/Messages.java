package com.owasp.demo.util;

import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;

/**
 * Loads page text from messages.yml once, at class load.
 */
public final class Messages {

    private static final Map<String, Object> ROOT = load();

    private Messages() {}

    private static Map<String, Object> load() {
        try (InputStream in = Messages.class.getClassLoader().getResourceAsStream("messages.yml")) {
            if (in == null) throw new IllegalStateException("messages.yml not found");
            return new Yaml().load(in);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read messages.yml", e);
        }
    }

    /**
     * @param key dotted key path, such as "xss.title"
     * @return the text for the key
     * @throws IllegalStateException if the key is missing
     */
    public static String get(String key) {
        return ConfigUtil.getString(ROOT, key);
    }

    /**
     * @param key dotted key path of a YAML list of maps, such as "cards"
     * @return the list rows
     */
    public static List<Map<String, String>> getList(String key) {
        return ConfigUtil.getMapList(ROOT, key);
    }
}
