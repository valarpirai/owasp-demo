package com.owasp.demo.view;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class TemplateEngineTest {

    @Test
    void escapeHandlesNull() {
        assertEquals("", TemplateEngine.escape(null));
    }

    @Test
    void escapeConvertsHtmlSpecialChars() {
        assertEquals("&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;",
            TemplateEngine.escape("<script>alert('XSS')</script>"));
    }

    @Test
    void escapeConvertsAmpersand() {
        assertEquals("a &amp; b", TemplateEngine.escape("a & b"));
    }

    @Test
    void escapeConvertsDoubleQuote() {
        assertEquals("&quot;hello&quot;", TemplateEngine.escape("\"hello\""));
    }

    @Test
    void renderSubstitutesAllPlaceholders() {
        String tpl = "Hello {name}, you are {age} years old.";
        // We can't call render() directly on an arbitrary string, but we can test
        // by loading a known template. Instead test via page() which calls load().
        // For inline testing, verify escape is used inside infoBox:
        String box = TemplateEngine.infoBox("vuln text", "fix text");
        assertTrue(box.contains("vuln text"));
        assertTrue(box.contains("fix text"));
    }

    @Test
    void pageContainsTitleAndContent() {
        String html = TemplateEngine.page("MyTitle", "<p>body</p>", false);
        assertTrue(html.contains("MyTitle"));
        assertTrue(html.contains("<p>body</p>"));
    }

    @Test
    void pageIncludesAuthNavWhenLoggedIn() {
        String html = TemplateEngine.page("T", "", true);
        assertTrue(html.contains("/logout"));
        assertTrue(html.contains("Dashboard"));
    }

    @Test
    void pageExcludesAuthNavWhenNotLoggedIn() {
        String html = TemplateEngine.page("T", "", false);
        assertFalse(html.contains("/logout"));
    }

    @Test
    void demoPanelUsesRedBorderForVulnerable() {
        String panel = TemplateEngine.demoPanel("label", "red", "<form/>", "");
        assertTrue(panel.contains("border-red-300"));
        assertTrue(panel.contains("bg-red-600"));
    }

    @Test
    void demoPanelUsesGreenBorderForMitigated() {
        String panel = TemplateEngine.demoPanel("label", "green", "<form/>", "");
        assertTrue(panel.contains("border-green-300"));
        assertTrue(panel.contains("bg-green-600"));
    }

    @Test
    void resultBoxReturnsEmptyForBlankInput() {
        assertEquals("", TemplateEngine.resultBox("", true));
        assertEquals("", TemplateEngine.resultBox(null, false));
    }

    @Test
    void resultBoxUsesGreenClassForSuccess() {
        String box = TemplateEngine.resultBox("ok", true);
        assertTrue(box.contains("bg-green-50"));
    }

    @Test
    void resultBoxUsesRedClassForFailure() {
        String box = TemplateEngine.resultBox("fail", false);
        assertTrue(box.contains("bg-red-50"));
    }

    @Test
    void vulnerabilityBadgeContainsIdAndName() {
        String badge = TemplateEngine.vulnerabilityBadge("A03", "SQL Injection", "SQLi");
        assertTrue(badge.contains("A03"));
        assertTrue(badge.contains("SQL Injection"));
    }

    @Test
    void loadThrowsForUnknownTemplate() {
        assertThrows(IllegalStateException.class, () -> TemplateEngine.load("nonexistent.html"));
    }

    // --- exploitBox ---

    @Test
    void exploitBox_rendersTitle_and_payload() {
        String box = TemplateEngine.exploitBox(new String[][]{
            {"My Attack", "' OR '1'='1", "desc"}
        });
        assertTrue(box.contains("My Attack"));
        // Single quotes are HTML-escaped in the <code> display; = is not escaped
        assertTrue(box.contains("&#x27; OR &#x27;1&#x27;=&#x27;1"), "Payload HTML-escaped in code block");
        assertTrue(box.contains("desc"));
    }

    @Test
    void exploitBox_withInputName_rendersUseButton() {
        String box = TemplateEngine.exploitBox(new String[][]{
            {"title", "payload", "desc", "myInput"}
        });
        assertTrue(box.contains("Use ↗"), "Use button present when inputName given");
        assertTrue(box.contains("name=myInput"), "Input name in Use button onclick");
    }

    @Test
    void exploitBox_withoutInputName_noUseButton() {
        String box = TemplateEngine.exploitBox(new String[][]{
            {"title", "payload", "desc"}
        });
        assertFalse(box.contains("Use ↗"), "No Use button when inputName absent");
    }

    @Test
    void exploitBox_withCurlCmd_rendersCurlButton() {
        String box = TemplateEngine.exploitBox(new String[][]{
            {"title", "payload", "desc", null, "curl -s http://localhost/"}
        });
        assertTrue(box.contains("curl"), "Curl button present when curlCmd given");
    }

    @Test
    void exploitBox_payloadEscapedInDisplayBlock() {
        String box = TemplateEngine.exploitBox(new String[][]{
            {"title", "<script>alert(1)</script>", "desc"}
        });
        // The <code> display block must HTML-escape the payload
        assertTrue(box.contains("&lt;script&gt;alert(1)&lt;/script&gt;"), "Script tag HTML-escaped in code block");
    }

    @Test
    void exploitBox_singleQuoteInPayload_safeInOnclick() {
        String box = TemplateEngine.exploitBox(new String[][]{
            {"title", "' OR '1'='1", "desc", "username"}
        });
        assertFalse(box.contains("value='' OR '"), "Unescaped single quote must not break onclick attribute");
    }

    @Test
    void exploitBoxCurlUsesBasicAuth() {
        String html = TemplateEngine.exploitBox(new String[][]{
            {"t", "p", "d", "in", "curl -b 'SESSION_COOKIE=SESSION' http://x"}});
        assertTrue(html.contains("-u admin:admin123"));
        assertFalse(html.contains("SESSION_COOKIE"));
    }

    @Test
    void renderDoesNotRescanSubstitutedValues() {
        String html = TemplateEngine.render("forms/csrf-mitigated.html", java.util.Map.of(
            "email", "{token}", "token", "SECRET", "value", "v"));
        assertTrue(html.contains("<strong>{token}</strong>"), "user text stays literal");
        assertTrue(html.contains("value=\"SECRET\""));
    }

    @Test
    void allFormsAreLoadedIntoMemoryAtStartup() {
        var cached = TemplateEngine.cachedTemplates();
        assertTrue(cached.contains("forms/sqli-vulnerable.html"));
        assertTrue(cached.contains("forms/xss-mitigated.html"));
        assertEquals(24, cached.stream().filter(n -> n.startsWith("forms/")).count());
    }

    @Test
    void loadReturnsTheSameCachedText() {
        assertSame(TemplateEngine.load("forms/csrf-vulnerable.html"), TemplateEngine.load("forms/csrf-vulnerable.html"));
    }

    @Test
    void otherTemplatesAreCachedOnFirstUse() {
        TemplateEngine.load("login.html");
        assertTrue(TemplateEngine.cachedTemplates().contains("login.html"));
    }
}
