package dev.octri;

import java.lang.reflect.Array;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;
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

    private static final int MAX_IDEMPOTENCY_KEY_LENGTH = 256;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final HttpClient HTTP = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(2))
        .build();
    private static final Pattern TRACEPARENT = Pattern.compile(
        "^00-([0-9a-fA-F]{32})-([0-9a-fA-F]{16})-[0-9a-fA-F]{2}$"
    );
    private static volatile Config config;

    /**
     * Keys whose value never leaves the process. Compared against the key with
     * case and separators removed, so {@code api_key}, {@code apiKey} and
     * {@code API-KEY} all match {@code apikey}, and the test is a substring one,
     * so {@code stripeSecretKey} matches too.
     */
    private static final List<String> SCRUB_KEYS = Collections.unmodifiableList(Arrays.asList(
        "password", "passwd", "passphrase", "secret", "token", "apikey",
        "authorization", "credential", "cookie", "session", "privatekey",
        "accesskey", "cardnumber", "creditcard", "cvv", "ssn"));

    private static final String REDACTED = "[redacted]";
    private static final String TRUNCATED = "[truncated]";

    /** Deep enough for real context maps, shallow enough to stay cheap. */
    private static final int MAX_SCRUB_DEPTH = 8;

    private static final Pattern BEARER =
        Pattern.compile("\\bbearer\\s+[\\w.~+/-]+=*", Pattern.CASE_INSENSITIVE);
    private static final Pattern JWT = Pattern.compile("\\beyJ[\\w-]+\\.[\\w-]+\\.[\\w-]+");
    private static final Pattern DIGIT_RUN = Pattern.compile("\\b(?:\\d[ -]?){12,18}\\d\\b");
    private static final Pattern EMAIL = Pattern.compile("[\\w.%+-]+@[\\w-]+(?:\\.[\\w-]+)+");
    private static final Pattern NON_ALPHANUMERIC = Pattern.compile("[^a-z0-9]");

    private static final List<String> EXTRA_SCRUB_KEYS = new CopyOnWriteArrayList<>();

    private static volatile Function<Map<String, Object>, Map<String, Object>> beforeSend;

    /**
     * Connection settings for one Octri monitoring project.
     *
     * <p>Hosted users can copy the URL, token and environment from the
     * Monitoring connection settings in the dashboard.</p>
     */
    public static final class Config {
        /** Base URL of the monitoring backend, stored without a trailing slash. */
        public final String url;
        /** Optional only for open self-hosted ingestion. Hosted Octri requires it. */
        public final String token;
        /** Dashboard project id that received events and spans are filed under. */
        public final String environment;
        /** Release this process is running, such as a commit SHA, or null. */
        public final String release;

        /**
         * Creates settings with no release identifier.
         *
         * @param url base URL of the monitoring backend
         * @param token project ingest token, or null for open self-hosted ingestion
         * @param environment dashboard project id to file telemetry under
         */
        public Config(String url, String token, String environment) {
            this(url, token, environment, null);
        }

        /**
         * Creates settings for one monitoring project.
         *
         * <p>Trailing slashes on {@code url} are removed, so {@code https://example.com}
         * and {@code https://example.com/} behave identically. A null {@code url}
         * becomes the empty string.</p>
         *
         * @param url base URL of the monitoring backend
         * @param token project ingest token, or null for open self-hosted ingestion
         * @param environment dashboard project id to file telemetry under
         * @param release release identifier reported with each event, or null
         */
        public Config(String url, String token, String environment, String release) {
            this.url = trimTrailingSlash(url);
            this.token = token;
            this.environment = environment;
            this.release = release;
        }
    }

    /**
     * Identifies one W3C distributed trace, and the span that called into
     * this process.
     */
    public static final class TraceContext {
        /** Hexadecimal id, 32 characters long, shared by every span in the trace. */
        public final String traceId;
        /**
         * Hexadecimal id, 16 characters long, of the span that called this process.
         *
         * <p>Null when this process started the trace.</p>
         */
        public final String parentSpanId;

        /**
         * Creates a context for one trace.
         *
         * @param traceId id shared by every span in the trace
         * @param parentSpanId id of the calling span, or null to start a trace
         */
        public TraceContext(String traceId, String parentSpanId) {
            this.traceId = traceId;
            this.parentSpanId = parentSpanId;
        }
    }

    /** Optional enrichment accepted by {@link #captureEvent(String, EventOptions)}. */
    public static final class EventOptions {
        /** Creates a set of event options with every field unset. */
        public EventOptions() {}

        /** When the event happened, as an ISO-8601 string. Defaults to the time of the call. */
        public String timestamp;
        /** Severity, such as {@code info}, {@code warning} or {@code error}. */
        public String level = "info";
        /** OpenAPI operation id the event belongs to. */
        public String operationId;
        /** HTTP method of the request the event describes. */
        public String method;
        /** Request path the event describes. */
        public String path;
        /** HTTP status code the request ended with. */
        public Integer statusCode;
        /** How long the described work took, in milliseconds. */
        public Double latencyMs;
        /** Retry number, counting from 1 for the first attempt. */
        public Integer attempt;
        /** Your own correlation id for the request. */
        public String requestId;
        /** Who the event happened to, such as a map holding an {@code id}. */
        public Map<String, Object> user;
        /**
         * Searchable keys and values, such as region or plan.
         *
         * <p>Octri sets {@code octri.origin} itself; these are merged over it.</p>
         */
        public Map<String, Object> tags;
        /** Free-form detail shown alongside the event in the dashboard. */
        public Map<String, Object> context;
        /** Steps leading up to the event, oldest first. */
        public List<Map<String, Object>> breadcrumbs;
        /** Overrides how the dashboard groups this event with similar ones. */
        public String fingerprint;
        /** Trace the event belongs to, usually from {@link Octri#traceFromHeader(String)}. */
        public TraceContext trace;
        /** Span within that trace the event was raised in. */
        public String spanId;
        /**
         * Idempotency key for the delivery.
         *
         * <p>Pass the same value when retrying a send so the backend stores it once.
         * A value that is null, empty, or carries a carriage return or newline is
         * replaced with a random id.</p>
         */
        public String eventId;
    }

    /** Optional request and trace metadata for a captured exception. */
    public static final class ErrorOptions {
        /** Creates a set of error options with every field unset. */
        public ErrorOptions() {}

        /** Severity, such as {@code error} or {@code fatal}. */
        public String level = "error";
        /** OpenAPI operation id the failure happened under. */
        public String operationId;
        /** HTTP method of the request that failed. */
        public String method;
        /** Request path that failed. */
        public String path;
        /** HTTP status code the failed request ended with. */
        public Integer statusCode;
        /**
         * Trace to file the error under, usually from {@link Octri#traceFromHeader(String)}.
         *
         * <p>When null, the error starts a new trace of its own.</p>
         */
        public TraceContext trace;
    }

    /** A completed trace span. Times are ISO-8601 strings. */
    public static final class Span {
        /** Creates an empty span. Fill in the required fields before capture. */
        public Span() {}

        /** Id of the trace this span belongs to. Required. */
        public String traceId;
        /** Id of this span, unique within the trace. Required. */
        public String spanId;
        /** Id of the enclosing span, or null when this is the root of the trace. */
        public String parentSpanId;
        /** Readable name for the work, such as {@code orders.list}. Required. */
        public String name;
        /** Side of the call the span was recorded on. */
        public String service = "server";
        /** OpenAPI operation id the span belongs to. */
        public String operationId;
        /** When the work started, as an ISO-8601 string. Required. */
        public String startTime;
        /** When the work finished, as an ISO-8601 string, or null while it runs. */
        public String endTime;
        /** How the work ended, such as {@code ok} or {@code error}. */
        public String status = "ok";
    }

    /**
     * Points every later call at the project described by {@code value}.
     *
     * <p>Call this once at startup. Until it runs, the capture methods return
     * without sending anything. Calling it again replaces the settings used by
     * subsequent calls.</p>
     *
     * @param value the settings to use, or null to stop reporting
     */
    public static void init(Config value) {
        config = value;
    }

    /**
     * Reads a W3C {@code traceparent} header into a trace context.
     *
     * <p>Returns the trace and parent span carried by {@code value} when it is
     * a well-formed version {@code 00} header. Returns a context holding a
     * fresh random trace id and no parent when the header is null, malformed,
     * or carries an all-zero trace or parent id, so the caller always gets a
     * usable trace.</p>
     *
     * @param value the inbound {@code traceparent} header, or null
     * @return the trace to report under, never null
     */
    public static TraceContext traceFromHeader(String value) {
        Matcher match = value == null ? null : TRACEPARENT.matcher(value.trim());
        if (match != null && match.matches()
            && !allZeros(match.group(1))
            && !allZeros(match.group(2))) {
            return new TraceContext(match.group(1).toLowerCase(), match.group(2).toLowerCase());
        }
        return new TraceContext(randomHex(16), null);
    }

    /**
     * Logs a standalone event with no extra detail.
     *
     * @param message what happened; ignored when null
     */
    public static void captureEvent(String message) {
        captureEvent(message, new EventOptions());
    }

    /**
     * Logs a standalone event, without depending on a generated Octri SDK.
     *
     * <p>Returns immediately; the send happens in the background. Does nothing
     * when {@link #init(Config)} has not run.</p>
     *
     * @param message what happened; ignored when null
     * @param options extra detail to attach, or null for the defaults
     */
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

    /**
     * Reports {@code error} with no request or trace detail.
     *
     * <p>The error starts a trace of its own. Returns immediately; the send
     * happens in the background.</p>
     *
     * @param error the exception to report; ignored when null
     */
    public static void captureError(Throwable error) {
        captureError(error, new ErrorOptions());
    }

    /**
     * Reports an exception, with one symbolic frame per line of its stack.
     *
     * <p>Frames outside {@code java.}, {@code jdk.} and {@code sun.} are marked
     * as in-app, so the dashboard shows your own code first. Files the error
     * under the trace in {@code options}, or under a new trace when none is
     * given. Returns immediately; the send happens in the background. Does
     * nothing when {@link #init(Config)} has not run.</p>
     *
     * @param error the exception to report; ignored when null
     * @param options request and trace detail, or null for the defaults
     */
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

    /**
     * Records a finished span as one bar in the dashboard request waterfall.
     *
     * <p>Ignores a span whose trace id, span id, name or start time is empty.
     * Returns immediately; the send happens in the background. Does nothing
     * when {@link #init(Config)} has not run.</p>
     *
     * @param span the finished span to report; ignored when null
     */
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

    /**
     * Redacts more key names, on top of the built-in list. Matching ignores case
     * and separators and is a substring test, so {@code account} also covers
     * {@code accountNumber}.
     *
     * <pre>Octri.addScrubFields("accountNumber", "otp");</pre>
     */
    public static void addScrubFields(String... fields) {
        for (String field : fields) {
            String key = normalizeKey(field);
            if (!key.isEmpty() && !EXTRA_SCRUB_KEYS.contains(key)) {
                EXTRA_SCRUB_KEYS.add(key);
            }
        }
    }

    /**
     * Runs a hook on every payload just before it is sent. Return the payload
     * (editing it is fine) to send it, or {@code null} to drop the event:
     *
     * <pre>Octri.setBeforeSend(payload -&gt; "/health".equals(payload.get("path")) ? null : payload);</pre>
     *
     * <p>Redaction still runs afterwards, so a hook cannot leak a credential by
     * accident. Pass {@code null} to remove the hook.
     */
    public static void setBeforeSend(Function<Map<String, Object>, Map<String, Object>> hook) {
        beforeSend = hook;
    }

    private static String normalizeKey(String key) {
        if (key == null) {
            return "";
        }
        return NON_ALPHANUMERIC.matcher(key.toLowerCase(Locale.ROOT)).replaceAll("");
    }

    private static boolean isSecretKey(Object key) {
        String normalized = normalizeKey(String.valueOf(key));
        if (normalized.isEmpty()) {
            return false;
        }
        for (String candidate : SCRUB_KEYS) {
            if (normalized.contains(candidate)) {
                return true;
            }
        }
        for (String candidate : EXTRA_SCRUB_KEYS) {
            if (normalized.contains(candidate)) {
                return true;
            }
        }
        return false;
    }

    /** Tells a card number from the order ids and timestamps that look like one. */
    private static boolean passesLuhn(String digits) {
        int sum = 0;
        boolean doubling = false;
        for (int index = digits.length() - 1; index >= 0; index--) {
            int digit = digits.charAt(index) - '0';
            if (doubling) {
                digit *= 2;
                if (digit > 9) {
                    digit -= 9;
                }
            }
            sum += digit;
            doubling = !doubling;
        }
        return sum % 10 == 0;
    }

    /** Removes credentials and personal data that leaked into free text. */
    private static String scrubText(String value) {
        if (value.isEmpty()) {
            return value;
        }
        String scrubbed = BEARER.matcher(value).replaceAll(Matcher.quoteReplacement(REDACTED));
        scrubbed = JWT.matcher(scrubbed).replaceAll(Matcher.quoteReplacement(REDACTED));

        Matcher runs = DIGIT_RUN.matcher(scrubbed);
        StringBuffer withoutCards = new StringBuffer();
        while (runs.find()) {
            String run = runs.group();
            String digits = run.replaceAll("\\D", "");
            runs.appendReplacement(
                withoutCards, Matcher.quoteReplacement(passesLuhn(digits) ? REDACTED : run));
        }
        runs.appendTail(withoutCards);

        return EMAIL.matcher(withoutCards.toString()).replaceAll(Matcher.quoteReplacement(REDACTED));
    }

    /**
     * Redacts credential-shaped keys anywhere in the payload, and strips secrets
     * out of the free text around them. {@code user} is the field you
     * deliberately fill with an identity, so its strings are left alone; its
     * keys are still checked.
     */
    private static Object scrubValue(Object value, int depth, boolean text) {
        if (value instanceof String) {
            return text ? scrubText((String) value) : value;
        }
        if (value instanceof Map) {
            if (depth >= MAX_SCRUB_DEPTH) {
                return TRUNCATED;
            }
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                String key = String.valueOf(entry.getKey());
                out.put(key, isSecretKey(key)
                    ? REDACTED
                    : scrubValue(entry.getValue(), depth + 1, text && !"user".equals(key)));
            }
            return out;
        }
        if (value instanceof Iterable) {
            if (depth >= MAX_SCRUB_DEPTH) {
                return TRUNCATED;
            }
            List<Object> out = new ArrayList<>();
            for (Object item : (Iterable<?>) value) {
                out.add(scrubValue(item, depth + 1, text));
            }
            return out;
        }
        if (value != null && value.getClass().isArray()) {
            if (depth >= MAX_SCRUB_DEPTH) {
                return TRUNCATED;
            }
            int length = Array.getLength(value);
            List<Object> out = new ArrayList<>(length);
            for (int index = 0; index < length; index++) {
                out.add(scrubValue(Array.get(value, index), depth + 1, text));
            }
            return out;
        }
        return value;
    }

    /**
     * The last thing every payload passes through. Both the hook and the
     * redaction live here rather than in the capture methods, so nothing can be
     * reported around them.
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> scrubPayload(Map<String, Object> payload) {
        Function<Map<String, Object>, Map<String, Object>> hook = beforeSend;
        Map<String, Object> hooked = payload;
        if (hook != null) {
            hooked = hook.apply(payload);
            if (hooked == null) {
                return null;
            }
        }
        return (Map<String, Object>) scrubValue(hooked, 0, true);
    }

    private static void post(Config cfg, String path, Map<String, Object> payload, String idempotencyKey) {
        try {
            if (!safeIdempotencyKey(idempotencyKey)
                || (cfg.token != null && !cfg.token.isEmpty() && !safeHeaderValue(cfg.token))) {
                return;
            }
            Map<String, Object> scrubbed = scrubPayload(payload);
            if (scrubbed == null) {
                return;
            }
            HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(cfg.url + path))
                .timeout(Duration.ofSeconds(5))
                .header("content-type", "application/json")
                .header("idempotency-key", idempotencyKey)
                .POST(HttpRequest.BodyPublishers.ofString(toJson(scrubbed)))
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
        return safeIdempotencyKey(value) ? value : randomHex(16);
    }

    /**
     * A caller-supplied event id becomes the idempotency-key header, so it is
     * bounded as well as newline-free.
     */
    private static boolean safeIdempotencyKey(String value) {
        return safeHeaderValue(value)
            && value.getBytes(StandardCharsets.UTF_8).length <= MAX_IDEMPOTENCY_KEY_LENGTH;
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
