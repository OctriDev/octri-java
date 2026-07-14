# Octri Monitoring for Java

Dependency-free Java 11+ monitoring with standalone events, exception capture,
W3C trace propagation, and span ingestion.

```java
import dev.octri.Octri;

Octri.init(new Octri.Config(
    "https://monitoring.example.com",
    System.getenv("OCTRI_TOKEN"),
    "<your project id>",
    System.getenv("GIT_SHA")
));

Octri.EventOptions event = new Octri.EventOptions();
event.tags = Map.of("region", "eu-west", "plan", "growth");
event.context = Map.of("orderId", order.id(), "total", order.total());
Octri.captureEvent("checkout.completed", event);
```

`captureEvent` works without a generated API SDK. `captureError` sends symbolic
Java stack frames, `traceFromHeader` continues a W3C trace, and `captureSpan`
reports a completed waterfall span. Delivery is asynchronous and best-effort.

Hosted users can copy the project-scoped URL, token, and environment from the
Monitoring connection settings (or its API). Pass `null` as the token only for
an open self-hosted endpoint. Every request carries an idempotency key.
