package com.owasp.demo.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MessagesTest {

    @Test
    void getReturnsTextWithMarkupAndUnicode() {
        assertTrue(Messages.get("sqli.info.explanation").contains("<code>"));
        assertTrue(Messages.get("sqli.panel.vulnerable").startsWith("Vulnerable —"));
    }

    @Test
    void cardsLoadInOrder() {
        assertEquals(13, Messages.getList("cards").size());
        assertEquals("A01", Messages.getList("cards").get(0).get("id"));
    }

    @Test
    void getThrowsForMissingKey() {
        assertThrows(IllegalStateException.class, () -> Messages.get("no.such.key"));
    }
}
