# dev.octri:octri-monitoring (Java)

**Error and performance monitoring for Java services.** Report a caught
`Throwable` with its stack frames, emit your own application events, time spans
into a request waterfall, and continue a W3C distributed trace that started in
whichever client called you.

Octri turns an OpenAPI spec into a documentation site, client SDKs for ten
languages, an MCP server your AI assistant can call, and monitoring for the
API behind them. This library is the Java monitoring runtime, and it works on
its own: a generated Octri API SDK is not required. See
[octri.dev/monitoring](https://octri.dev/monitoring).

Java 11 or newer. No runtime dependencies: transport is `java.net.http`.

## Install

```xml
<dependency>
  <groupId>dev.octri</groupId>
  <artifactId>octri-monitoring</artifactId>
  <version>${octri.version}</version>
</dependency>
```

```groovy
implementation "dev.octri:octri-monitoring:$octriVersion"
```

Set the version to the current release on Maven Central.

## Setup

Call `init` once during startup.

```java
import dev.octri.Octri;

Octri.init(new Octri.Config(
    "https://monitoring.example.com",   // your monitoring base URL
    System.getenv("OCTRI_TOKEN"),       // your project ingest token
    "<your project id>",                // the dashboard project id
    System.getenv("GIT_SHA")            // optional
));
```

Hosted users copy the project-scoped URL, token, and environment from the
Monitoring connection settings in the dashboard. Pass `null` for the token only
when you point at an open self-hosted ingest endpoint.

Every call is asynchronous, best effort, and carries an idempotency key.
Transport failures are swallowed, so a monitoring outage cannot affect the
service it is watching.

## Application events

```java
Octri.captureEvent("checkout.completed");
```

Or with detail:

```java
Octri.EventOptions options = new Octri.EventOptions();
options.level = "info";
options.user = Map.of("id", customer.id());
options.tags = Map.of("region", "eu-west", "plan", "growth");
options.context = Map.of("orderId", order.id());

Octri.captureEvent("checkout.completed", options);
```

`EventOptions` also carries `breadcrumbs`, `fingerprint`, `operationId`,
`method`, `path`, `statusCode`, `latencyMs`, `attempt`, `requestId`, and
`timestamp`. Setting `eventId` makes a retried delivery idempotent.

## Errors

```java
try {
    handler.handle(request);
} catch (Throwable error) {
    Octri.ErrorOptions options = new Octri.ErrorOptions();
    options.method = "POST";
    options.path = "/orders";
    options.statusCode = 500;

    Octri.captureError(error, options);
    throw error;
}
```

`Octri.captureError(error)` reports without the request metadata.

## Joining the caller's trace

Your generated client SDK sends `traceparent: 00-<traceId>-<spanId>-01` on every
request. Read it on the way in and set it as `trace`, and the dashboard groups
the client call and the server error under one `traceId`: the request that
failed, beside the frame that threw.

```java
Octri.TraceContext trace = Octri.traceFromHeader(request.getHeader("traceparent"));

Octri.ErrorOptions options = new Octri.ErrorOptions();
options.trace = trace;
Octri.captureError(error, options);
```

`traceFromHeader(null)` starts a fresh trace, so the same code path works for
traffic that arrives without a header.

## Spans

A span is a completed unit of work with ISO-8601 timestamps. Report one per
request to get the waterfall, and one per sub-operation to see where the time
went inside it.

```java
String started = Instant.now().toString();
List<Order> rows = repository.list();

Octri.Span span = new Octri.Span();
span.traceId = trace.traceId;
span.spanId = spanId;
span.parentSpanId = trace.parentSpanId;
span.name = "orders.list";
span.operationId = "listOrders";
span.startTime = started;
span.endTime = Instant.now().toString();

Octri.captureSpan(span);
```

Spans sharing a `traceId` nest by `parentSpanId` in the dashboard waterfall.

---

## The rest of Octri

| Product | What it does |
|---|---|
| [API Studio](https://octri.dev/api-studio) | Your OpenAPI spec becomes a hosted documentation site with a live request playground, editable page by page. |
| [SDK Studio](https://octri.dev/sdk-studio) | The same spec becomes client libraries for ten languages, versioned and released together. |
| [MCP](https://octri.dev/mcp) | Your endpoints and docs become tools an AI assistant can call, generated from the same spec. |
| [Monitoring](https://octri.dev/monitoring) | Errors, traces, uptime and releases for the API, joined to the SDK calls that reached it. |

### Monitoring runtimes

[Node](https://github.com/octridev/octri-node) ·
[Python](https://github.com/octridev/octri-python) ·
[Go](https://github.com/octridev/octri-go) ·
[Ruby](https://github.com/octridev/octri-ruby) ·
[Rust](https://github.com/octridev/octri-rust) ·
[PHP](https://github.com/octridev/octri-php) ·
[Java](https://github.com/octridev/octri-java) ·
[Kotlin](https://github.com/octridev/octri-kotlin) ·
[Swift](https://github.com/octridev/octri-swift) ·
[Dart](https://github.com/octridev/octri-dart)

[Documentation](https://docs.octri.dev/docs) ·
[Pricing](https://octri.dev/pricing) ·
[Changelog](https://docs.octri.dev/changelog)

MIT licensed.
