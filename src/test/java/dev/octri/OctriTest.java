package dev.octri;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

final class OctriTest {
    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) server.stop(0);
    }

    @Test
    void parsesValidTraceparentAndRejectsZeroIdentifiers() {
        Octri.TraceContext valid = Octri.traceFromHeader(
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01"
        );
        assertEquals("4bf92f3577b34da6a3ce929d0e0e4736", valid.traceId);
        assertEquals("00f067aa0ba902b7", valid.parentSpanId);

        Octri.TraceContext invalid = Octri.traceFromHeader(
            "00-00000000000000000000000000000000-0000000000000000-01"
        );
        assertTrue(invalid.traceId.matches("[0-9a-f]{32}"));
        assertFalse(invalid.traceId.matches("0{32}"));
        assertNull(invalid.parentSpanId);
    }

    @Test
    void replacesAnOversizedEventId() throws Exception {
        CountDownLatch received = new CountDownLatch(1);
        AtomicReference<String> idempotencyKey = new AtomicReference<>();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/ingest", exchange -> {
            idempotencyKey.set(exchange.getRequestHeaders().getFirst("idempotency-key"));
            exchange.sendResponseHeaders(202, -1);
            exchange.close();
            received.countDown();
        });
        server.start();

        Octri.init(new Octri.Config(
            "http://127.0.0.1:" + server.getAddress().getPort() + "/",
            "project-token",
            "project-1"
        ));
        Octri.EventOptions options = new Octri.EventOptions();
        options.eventId = "e".repeat(257);
        Octri.captureEvent("checkout.completed", options);

        assertTrue(received.await(3, TimeUnit.SECONDS));
        assertTrue(idempotencyKey.get().matches("[0-9a-f]{32}"));
    }

    @Test
    void sendsScopedIdempotentJsonWithoutHeaderInjection() throws Exception {
        CountDownLatch received = new CountDownLatch(1);
        AtomicReference<String> body = new AtomicReference<>();
        AtomicReference<String> idempotencyKey = new AtomicReference<>();
        AtomicReference<String> authorization = new AtomicReference<>();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/ingest", exchange -> {
            body.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            idempotencyKey.set(exchange.getRequestHeaders().getFirst("idempotency-key"));
            authorization.set(exchange.getRequestHeaders().getFirst("authorization"));
            exchange.sendResponseHeaders(202, -1);
            exchange.close();
            received.countDown();
        });
        server.start();

        Octri.init(new Octri.Config(
            "http://127.0.0.1:" + server.getAddress().getPort() + "/",
            "project-token",
            "project-1"
        ));
        Octri.EventOptions options = new Octri.EventOptions();
        options.eventId = "unsafe\r\nX-Injected: true";
        Map<String, Object> tags = new LinkedHashMap<>();
        tags.put("numbers", new int[] {1, 2, 3});
        tags.put("notFinite", Double.NaN);
        options.tags = tags;
        Octri.captureEvent("checkout.completed", options);

        assertTrue(received.await(3, TimeUnit.SECONDS));
        Matcher eventId = Pattern.compile("\\\"eventId\\\":\\\"([0-9a-f]{32})\\\"")
            .matcher(body.get());
        assertTrue(eventId.find());
        assertEquals(eventId.group(1), idempotencyKey.get());
        assertEquals("Bearer project-token", authorization.get());
        assertTrue(body.get().contains("\"environment\":\"project-1\""));
        assertTrue(body.get().contains("\"numbers\":[1,2,3]"));
        assertTrue(body.get().contains("\"notFinite\":null"));
    }
}
