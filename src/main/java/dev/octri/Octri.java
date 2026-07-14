package dev.octri;

import java.lang.reflect.Array;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Dependency-free Octri monitoring for Java applications.
 *
 * <p>All delivery is asynchronous and best-effort. A telemetry failure is
 * deliberately ignored and can never fail the host application.</p>
 */
public final class Octri {
    private Octri() {}

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final HttpClient HTTP = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(2))
        .build();
    private static final Pattern TRACEPARENT = Pattern.compile(
        "^00-([0-9a-fA-F]{32})-([0-9a-fA-F]{16})-[0-9a-fA-F]{2}$"
    );
    private static volatile Config config;

    public static final class Config {
        public final String url;
        /** Optional only for open self-hosted ingestion. Hosted Octri requires it. */
        public final String token;
        public final String environment;
        public final String release;

        public Config(String url, String token, String environment) {
            this(url, token, environment, null);
        }

        public Config(String url, String token, String environment, String release) {
            this.url = trimTrailingSlash(url);
            this.token = token;
            this.environment = environment;
            this.release = release;
        }
    }

    public static final class TraceContext {
        public final String traceId;
        public final String parentSpanId;

        public TraceContext(String traceId, String parentSpanId) {
            this.traceId = traceId;
            this.parentSpanId = parentSpanId;
        }
    }

    /** Optional enrichment accepted by {@link #captureEvent(String, EventOptions)}. */
    public static final class EventOptions {
        public String timestamp;
        public String level = "info";
        public String operationId;
        public String method;
        public String path;
        public Integer statusCode;
        public Double latencyMs;
        public Integer attempt;
        public String requestId;
        public Map<String, Object> user;
        public Map<String, Object> tags;
        public Map<String, Object> context;
        public List<Map<String, Object>> breadcrumbs;
        public String fingerprint;
        public TraceContext trace;
        public String spanId;
        public String eventId;
    }

    /** Optional request and trace metadata for a captured exception. */
    public static final class ErrorOptions {
        public String level = "error";
        public String operationId;
        public String method;
        public String path;
        public Integer statusCode;
        public TraceContext trace;
    }

    /** A completed trace span. Times are ISO-8601 strings. */
    public static final class Span {
        public String traceId;
        public String spanId;
        public String parentSpanId;
        public String name;
        public String service = "server";
        public String operationId;
        public String startTime;
        public String endTime;
        public String status = "ok";
    }

    /** Configure Octri once during application startup. */
    public static void init(Config value) {
        config = value;
    }

    /** Read a W3C traceparent header or create a fresh trace. */
    public static TraceContext traceFromHeader(String value) {
        Matcher match = value == null ? null : TRACEPARENT.matcher(value.trim());
        if (match != null && match.matches()
            && !allZeros(match.group(1))
            && !allZeros(match.group(2))) {
            return new TraceContext(match.group(1).toLowerCase(), match.group(2).toLowerCase());
        }
        return new TraceContext(randomHex(16), null);
    }

    /** Log a standalone event without depending on a generated Octri SDK. */
    public static void captureEvent(String message) {
        captureEvent(message, new EventOptions());
    }

    /** Log a standalone event without depending on a generated Octri SDK. */
    public static void captureEvent(String message, EventOptions options) {
        Config cfg = config;
        if (cfg == null || message == null) return;
        EventOptions value = options == null ? new EventOptions() : options;
        String eventId = safeEventId(value.eventId);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("eventId", eventId);
        payload.put("timestamp", orElse(value.timestamp, Instant.now().toString()));
        payload.put("level", orElse(value.level, "info"));
        payload.put("message", message);
        payload.put("environment", cfg.environment);
        put(payload, "release", cfg.release);
        put(payload, "operationId", value.operationId);
        put(payload, "method", value.method);
        put(payload, "path", value.path);
        put(payload, "statusCode", value.statusCode);
        put(payload, "latencyMs", value.latencyMs);
        put(payload, "attempt", value.attempt);
        put(payload, "requestId", value.requestId);
        put(payload, "user", value.user);
        Map<String, Object> tags = new LinkedHashMap<>();
        tags.put("octri.origin", "standalone");
        if (value.tags != null) tags.putAll(value.tags);
        payload.put("tags", tags);
        put(payload, "context", value.context);
        put(payload, "breadcrumbs", value.breadcrumbs);
        put(payload, "fingerprint", value.fingerprint);
        if (value.trace != null) put(payload, "traceId", value.trace.traceId);
        put(payload, "spanId", value.spanId);
        post(cfg, "/ingest", payload, eventId);
    }

    public static void captureError(Throwable error) {
        captureError(error, new ErrorOptions());
    }

    /** Capture an exception with symbolic Java stack frames. */
    public static void captureError(Throwable error, ErrorOptions options) {
        Config cfg = config;
        if (cfg == null || error == null) return;
        ErrorOptions value = options == null ? new ErrorOptions() : options;
        TraceContext trace = value.trace == null ? traceFromHeader(null) : value.trace;

        List<Map<String, Object>> frames = new ArrayList<>();
        for (StackTraceElement element : error.getStackTrace()) {
            Map<String, Object> frame = new LinkedHashMap<>();
            frame.put("function", element.getClassName() + "." + element.getMethodName());
            frame.put("filename", element.getFileName());
            frame.put("lineno", element.getLineNumber());
            frame.put("colno", 0);
            frame.put("inApp", !element.getClassName().startsWith("java.")
                && !element.getClassName().startsWith("jdk.")
                && !element.getClassName().startsWith("sun."));
            frames.add(frame);
        }
        Map<String, Object> exception = new LinkedHashMap<>();
        exception.put("name", error.getClass().getName());
        exception.put("message", String.valueOf(error.getMessage()));
        exception.put("frames", frames);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("eventId", randomHex(16));
        payload.put("timestamp", Instant.now().toString());
        payload.put("level", orElse(value.level, "error"));
        payload.put("environment", cfg.environment);
        put(payload, "release", cfg.release);
        payload.put("traceId", trace.traceId);
        payload.put("spanId", randomHex(8));
        payload.put("tags", Collections.singletonMap("octri.origin", "server"));
        payload.put("error", exception);
        put(payload, "operationId", value.operationId);
        put(payload, "method", value.method);
        put(payload, "path", value.path);
        put(payload, "statusCode", value.statusCode);
        post(cfg, "/ingest", payload, (String) payload.get("eventId"));
    }

    /** Report a completed distributed-trace span. */
    public static void captureSpan(Span span) {
        Config cfg = config;
        if (cfg == null || span == null
            || isBlank(span.traceId) || isBlank(span.spanId)
            || isBlank(span.name) || isBlank(span.startTime)) return;
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("traceId", span.traceId);
        payload.put("spanId", span.spanId);
        put(payload, "parentSpanId", span.parentSpanId);
        payload.put("environment", cfg.environment);
        payload.put("name", span.name);
        payload.put("service", orElse(span.service, "server"));
        put(payload, "operationId", span.operationId);
        payload.put("startTime", span.startTime);
        put(payload, "endTime", span.endTime);
        payload.put("status", orElse(span.status, "ok"));
        post(cfg, "/traces", payload, span.traceId + ":" + span.spanId);
    }

    private static void post(Config cfg, String path, Map<String, Object> payload, String idempotencyKey) {
        try {
            if (!safeHeaderValue(idempotencyKey)
                || (cfg.token != null && !cfg.token.isEmpty() && !safeHeaderValue(cfg.token))) {
                return;
            }
            HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(cfg.url + path))
                .timeout(Duration.ofSeconds(5))
                .header("content-type", "application/json")
                .header("idempotency-key", idempotencyKey)
                .POST(HttpRequest.BodyPublishers.ofString(toJson(payload)))
                ;
            if (cfg.token != null && !cfg.token.isEmpty()) {
                builder.header("authorization", "Bearer " + cfg.token);
            }
            HttpRequest request = builder.build();
            HTTP.sendAsync(request, HttpResponse.BodyHandlers.discarding())
                .exceptionally(ignored -> null);
        } catch (Throwable ignored) {
            // Monitoring must never affect the application.
        }
    }

    private static String randomHex(int bytes) {
        byte[] data = new byte[bytes];
        RANDOM.nextBytes(data);
        StringBuilder result = new StringBuilder(bytes * 2);
        for (byte value : data) result.append(String.format("%02x", value & 0xff));
        return result.toString();
    }

    private static String trimTrailingSlash(String value) {
        if (value == null) return "";
        int end = value.length();
        while (end > 0 && value.charAt(end - 1) == '/') end--;
        return value.substring(0, end);
    }

    private static String orElse(String value, String fallback) {
        return value == null || value.isEmpty() ? fallback : value;
    }

    private static String safeEventId(String value) {
        return safeHeaderValue(value) ? value : randomHex(16);
    }

    private static boolean safeHeaderValue(String value) {
        return value != null && !value.isEmpty()
            && value.indexOf('\r') < 0 && value.indexOf('\n') < 0;
    }

    private static boolean allZeros(String value) {
        for (int index = 0; index < value.length(); index++) {
            if (value.charAt(index) != '0') return false;
        }
        return true;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isEmpty();
    }

    private static void put(Map<String, Object> target, String key, Object value) {
        if (value != null) target.put(key, value);
    }

    private static String toJson(Object value) {
        if (value == null) return "null";
        if (value instanceof String) return '"' + escape((String) value) + '"';
        if (value instanceof Double && !Double.isFinite((Double) value)) return "null";
        if (value instanceof Float && !Float.isFinite((Float) value)) return "null";
        if (value instanceof Number || value instanceof Boolean) return value.toString();
        if (value instanceof Map) {
            StringBuilder out = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                if (!first) out.append(',');
                first = false;
                out.append(toJson(String.valueOf(entry.getKey()))).append(':').append(toJson(entry.getValue()));
            }
            return out.append('}').toString();
        }
        if (value instanceof Iterable) {
            StringBuilder out = new StringBuilder("[");
            boolean first = true;
            for (Object item : (Iterable<?>) value) {
                if (!first) out.append(',');
                first = false;
                out.append(toJson(item));
            }
            return out.append(']').toString();
        }
        if (value.getClass().isArray()) {
            StringBuilder out = new StringBuilder("[");
            int length = Array.getLength(value);
            for (int index = 0; index < length; index++) {
                if (index > 0) out.append(',');
                out.append(toJson(Array.get(value, index)));
            }
            return out.append(']').toString();
        }
        return toJson(String.valueOf(value));
    }

    private static String escape(String value) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
            }
        }
        return out.toString();
    }
}
