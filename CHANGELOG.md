# Changelog

## 1.1.0

- Payloads are now scrubbed before they are sent. Values under keys that name a
  credential (`password`, `secret`, `token`, `apiKey`, `authorization`,
  `cookie`, `ssn` and the rest) are replaced with `[redacted]` at any depth, and
  free text is swept for bearer tokens, JWTs, Luhn-valid card numbers and email
  addresses.
- `addScrubFields` adds your own key names to that list.
- `setBeforeSend` hands you each payload before it goes out; return
  `null` to drop the event. Redaction runs after the hook.
- The `user` field keeps the identity you set, since that is the point of it.
  Credential-shaped keys inside it are still redacted.

## 1.0.2

- A caller-supplied event id is capped at 256 bytes before it becomes the
  idempotency key header, matching the other Octri runtimes.

## 1.0.1

- Javadoc comments across the whole public API, so the published
  documentation artifact carries real content.

## 1.0.0

First public release.

- Error reporting with original source context for each in-app stack frame.
- Request and sub-span timing, drawn as a waterfall in the dashboard.
- W3C `traceparent` propagation, so a server error links to the client SDK
  error for the same request.
- Standalone events with idempotent, best-effort delivery.
