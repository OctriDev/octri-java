package dev.octri;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The bodies are asserted as text: the reporter writes its own JSON, and a
 * parser would only be another thing to keep in step with it.
 */
final class ScrubTest {
    private HttpServer server;
    private final LinkedBlockingQueue<String> bodies = new LinkedBlockingQueue<>();

    @BeforeEach
    void startServer() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/ingest", exchange -> {
            bodies.add(read(exchange.getRequestBody()));
            exchange.sendResponseHeaders(202, -1);
            exchange.close();
        });
        server.start();
        Octri.init(new Octri.Config(
            "http://127.0.0.1:" + server.getAddress().getPort() + "/", null, "project-1"));
    }

    @AfterEach
    void stopServer() {
        Octri.setBeforeSend(null);
        if (server != null) server.stop(0);
    }

    private static String read(InputStream stream) throws java.io.IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int count;
        while ((count = stream.read(buffer)) > 0) out.write(buffer, 0, count);
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    private String next() throws InterruptedException {
        String body = bodies.poll(3, TimeUnit.SECONDS);
        assertNotNull(body, "timed out waiting for an event");
        return body;
    }

    // ── Keys ────────────────────────────────────────────────────────────────

    @Test
    void redactsCredentialShapedKeysHoweverTheyAreSpelled() throws Exception {
        Map<String, Object> context = new LinkedHashMap<>();
        context.put("api_key", "sk_live_1");
        context.put("apiKey", "sk_live_2");
        context.put("X-API-KEY", "sk_live_3");
        context.put("stripeSecretKey", "sk_live_4");
        context.put("Authorization", "Bearer abc");
        context.put("refresh_token", "rt_1");
        context.put("cookie", "sid=1");
        context.put("orderId", "A-1024");
        context.put("author", "ada");

        Octri.EventOptions options = new Octri.EventOptions();
        options.context = context;
        Octri.captureEvent("checkout failed", options);

        String body = next();
        for (String key : Arrays.asList("api_key", "apiKey", "X-API-KEY", "stripeSecretKey",
            "Authorization", "refresh_token", "cookie")) {
            assertTrue(body.contains("\"" + key + "\":\"[redacted]\""), key + " in " + body);
        }
        assertFalse(body.contains("sk_live"), body);
        assertTrue(body.contains("\"orderId\":\"A-1024\""), body);
        assertTrue(body.contains("\"author\":\"ada\""), body);
    }

    @Test
    void redactsNestedAndListValues() throws Exception {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("authorization", "Bearer abc");
        Map<String, Object> upstream = new LinkedHashMap<>();
        upstream.put("headers", java.util.Collections.singletonList(header));
        Map<String, Object> context = new LinkedHashMap<>();
        context.put("upstream", upstream);

        Octri.EventOptions options = new Octri.EventOptions();
        options.context = context;
        Octri.captureEvent("upstream rejected the call", options);

        String body = next();
        assertTrue(body.contains("\"authorization\":\"[redacted]\""), body);
        assertFalse(body.contains("Bearer abc"), body);
    }

    @Test
    void addScrubFieldsIsAdditive() throws Exception {
        Octri.addScrubFields("accountNumber");
        Map<String, Object> context = new LinkedHashMap<>();
        context.put("accountNumber", "12345678");
        context.put("orderId", "A-1024");

        Octri.EventOptions options = new Octri.EventOptions();
        options.context = context;
        Octri.captureEvent("payout failed", options);

        String body = next();
        assertTrue(body.contains("\"accountNumber\":\"[redacted]\""), body);
        assertTrue(body.contains("\"orderId\":\"A-1024\""), body);
    }

    // ── Free text ───────────────────────────────────────────────────────────

    @Test
    void stripsSecretsThatLeakedIntoAMessage() throws Exception {
        Octri.captureEvent("401 from billing: Authorization: Bearer sk_live_abc123 rejected");
        String body = next();
        assertFalse(body.contains("sk_live_abc123"), body);
        assertTrue(body.contains("[redacted]"), body);

        Octri.captureEvent("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.7Hk2 expired");
        assertTrue(next().contains("\"message\":\"token [redacted] expired\""));

        Octri.captureEvent("no account for ada@example.com");
        assertTrue(next().contains("\"message\":\"no account for [redacted]\""));
    }

    @Test
    void stripsCardNumbersButNotOrderNumbers() throws Exception {
        Octri.captureEvent("charge 4242 4242 4242 4242 failed for order 1234567890123");

        String body = next();
        assertFalse(body.contains("4242"), body);
        assertTrue(body.contains("1234567890123"), body);
    }

    @Test
    void scrubsAnErrorMessage() throws Exception {
        Octri.captureError(new IllegalStateException("mail to ada@example.com bounced"));

        String body = next();
        assertFalse(body.contains("ada@example.com"), body);
        assertTrue(body.contains("mail to [redacted] bounced"), body);
    }

    // ── The user field ──────────────────────────────────────────────────────

    @Test
    void keepsUserIdentityButNotUserCredentials() throws Exception {
        Map<String, Object> user = new LinkedHashMap<>();
        user.put("id", "u_1");
        user.put("email", "ada@example.com");
        user.put("sessionToken", "st_1");

        Octri.EventOptions options = new Octri.EventOptions();
        options.user = user;
        Octri.captureEvent("profile update failed", options);

        String body = next();
        assertTrue(body.contains("\"email\":\"ada@example.com\""), body);
        assertTrue(body.contains("\"sessionToken\":\"[redacted]\""), body);
    }

    // ── setBeforeSend ───────────────────────────────────────────────────────

    @Test
    void beforeSendEditsThePayloadAndRedactionStillRunsAfterIt() throws Exception {
        Octri.setBeforeSend(payload -> {
            Map<String, Object> context = new LinkedHashMap<>();
            context.put("note", "call ada@example.com");
            payload.put("context", context);
            return payload;
        });
        Octri.captureEvent("build failed");

        assertTrue(next().contains("\"note\":\"call [redacted]\""));
    }

    @Test
    void beforeSendReturningNullDropsTheEvent() throws Exception {
        Octri.setBeforeSend(payload -> "noise".equals(payload.get("message")) ? null : payload);
        Octri.captureEvent("noise");
        Octri.captureEvent("signal");

        assertTrue(next().contains("\"message\":\"signal\""));
    }
}
