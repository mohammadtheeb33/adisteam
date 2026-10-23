# ADIS ingestion API

`apps/api` is the entry point for telemetry. It validates canonical security events
([EVENT_SCHEMA.md](EVENT_SCHEMA.md)), stamps them with server time, and enqueues them to
Kafka. Detection and ML inference happen asynchronously downstream, never in the request.

- Interactive documentation: `/docs` (Swagger UI) and `/redoc`.
- Machine-readable spec: `/openapi.json`. It is generated from the code and includes the
  canonical event schemas as components.

## Endpoints

| Method and path | Auth | Purpose | Success |
|---|---|---|---|
| `GET /health` | none | Liveness; checks no dependencies. | `200 {"status": "ok"}` |
| `GET /ready` | none | Readiness: a Kafka broker answers a metadata request within `API_PUBLISH_TIMEOUT_SECONDS`. Every call is a real broker round trip, so an outage shows up immediately. With `API_RATE_LIMIT_BACKEND=redis`, `checks.redis` is reported too, but it never makes the API unready (limiting falls back to the process). | `200` or `503`, with `{"status", "checks": {"kafka": "ok"\|"unavailable", "redis"?: ...}}` |
| `GET /metrics` | none | Prometheus metrics (when `PROMETHEUS_ENABLED`); see [Metrics](#metrics). | `200` text exposition format |
| `POST /api/v1/events` | bearer | Ingest one canonical event. | `202 {"status": "accepted", "event_id", "trace_id"}` |
| `POST /api/v1/events/batch` | bearer | Ingest `{"events": [...]}`, up to `API_MAX_BATCH_SIZE`. | `202` with `status` `accepted` or `partially_accepted` |

A `202` means the Kafka broker acknowledged every accepted event (`acks=all`). The event
is durable before the response is sent.

The API starts even when Kafka is unreachable: it connects in the background, retrying
with backoff (`api_kafka_connect_retry` logs), and answers `/ready` and event requests
with `503` until the broker is reached. It never has to be restarted by hand after a
broker outage at start-up.

### What the API does to each event

1. Validates it with the canonical codec. `schema_version` must be present; unknown
   fields are rejected; addresses, ports and timestamps are checked (see
   [EVENT_SCHEMA.md](EVENT_SCHEMA.md)).
2. **Overwrites `received_at` with server time.** Retention is keyed on this field, so a
   client-chosen value could get events purged early or kept forever.
3. Keeps the event's `trace_id` if present. Otherwise the event joins the request's
   trace, which is taken from a W3C `traceparent` header or newly created.
4. Publishes the event in an `EventEnvelope` to its accepted-telemetry topic
   (`telemetry_topic(category)`: `system_logs`, `auth_events` or
   `network_flows`), keyed by `host_id`, with provenance headers:
   `adis-ingest-client` (the authenticated client) and `adis-request-id`. The
   [normalizer](NORMALIZER.md) stores it and republishes it to `adis.security.events`.

### Batches

- Every event is validated independently.
  - Valid events are enqueued; invalid ones are listed in `rejected` with their
    `index`, `code` and `issues`, and the status is `partially_accepted`.
  - If **no** event is valid, the response is `422`.
- Events repeated within one batch (same `event_id`) are published once.
- **Retries are safe if every event carries its own `event_id`.** After a `503` or a
  timeout, resend the whole batch. Storage is idempotent on `event_id`, so events that were
  already enqueued are not duplicated. The id is optional in the schema and generated when
  absent, so a client that omits it gets a new event, not a duplicate, on every resend: give
  each event a stable id (the ADIS agent does).

```json
{
  "status": "partially_accepted",
  "accepted_count": 1,
  "rejected_count": 1,
  "accepted": [{"index": 0, "event_id": "0f8b0a8e-5d0c-4d7b-9d0e-2b8f3f0c9a11"}],
  "rejected": [
    {
      "index": 1,
      "code": "validation_failed",
      "issues": ["network.src_port: Input should be less than or equal to 65535"]
    }
  ]
}
```

## Authentication

`Authorization: Bearer <token>`. Tokens are issued per client in `API_INGEST_TOKENS`
(`client:token`, comma-separated).

- The server keeps only SHA-256 digests of the tokens, and tokens are never logged.
- The client id labels rate limits, logs and the `adis-ingest-client` header.
- A missing or unknown token gets `401` with `WWW-Authenticate: Bearer`.
- **Agent-bound tokens.** A client id of the form `agent-<agent uuid>` may submit only
  events whose `agent_id` is that UUID. Other events are rejected with
  `422 agent_mismatch` (in a batch, per event), so a stolen agent token cannot inject
  telemetry in another agent's name. Give each agent its own token this way; other
  client ids (connectors, tests) stay unbound.
- **Host-bound tokens.** The agent binding pins `agent_id`, not `host_id`, and everything
  downstream (features, baselines, threats, recommendations) is keyed by `host_id`. A
  client listed in `API_INGEST_CLIENT_HOSTS` (`client=host[|host...]`) may submit only
  events naming one of those hosts (an event without a host is refused too). Others are
  rejected with `422 host_mismatch` (in a batch, per event), so a stolen token cannot
  drive detection or responses against another host. In staging and production every
  `agent-<uuid>` client must be listed, or the API refuses to start (ARCHITECTURE.md
  OD-34). Unlisted clients, such as connectors, may still name any host: treat their
  tokens as trusted and, where a connector covers known hosts, list it as well.

This scheme is intentionally simple and replaceable. mTLS or JWTs are the planned next
step (ARCHITECTURE.md OD-16).

## Limits

| Limit | Setting | Exceeded |
|---|---|---|
| Request body | `API_MAX_REQUEST_BYTES` (default 1 MiB) | `413 payload_too_large`. The declared `Content-Length` is checked first, then the stream, so oversized bodies are never buffered. |
| Single event | 131,072 bytes (canonical schema) | `413 payload_too_large` |
| Events per batch | `API_MAX_BATCH_SIZE` (default 500) | `413 batch_too_large` |
| Rate | `API_RATE_LIMIT_EVENTS` per `API_RATE_LIMIT_WINDOW_SECONDS` per client (default 6000/60 s) | `429 rate_limited` with `Retry-After` |
| Kafka acknowledgement | `API_PUBLISH_TIMEOUT_SECONDS` (default 5 s) | `503 service_unavailable` with `Retry-After` |
| Concurrent requests | `API_MAX_CONCURRENT_REQUESTS` (default 256, uvicorn `limit_concurrency`) | `503` at once, instead of queuing without bound in memory |

### Rate limiting

- Budgets are counted in **events** (a batch of 50 costs 50) and kept per authenticated
  client in a token bucket. Refused requests are not charged.
- Successful responses carry `RateLimit-Limit`, `RateLimit-Remaining` and
  `RateLimit-Reset` (seconds until the budget is full again).
- The `RateLimiter` protocol (`apps/api/rate_limit.py`) is the extension point.
  `API_RATE_LIMIT_BACKEND` selects the implementation:
  - `memory` (default): an in-process token bucket, exact for one instance. With
    several replicas each one enforces its own budget.
  - `redis`: one budget per client shared by every replica, kept in Redis (`REDIS_*`
    settings) in atomic fixed windows of `API_RATE_LIMIT_WINDOW_SECONDS` (one Lua
    script checks and spends). If Redis fails, the request is limited by the
    in-process bucket instead (counted in `adis_api_rate_limit_fallbacks_total`,
    warning logged at most every 30 s), and Redis is left alone for 5 s, so an outage
    never adds its connect timeout to every request. Redis never blocks ingestion.

## Errors

Every error uses one envelope. Messages and issues name fields but never echo submitted
values.

```json
{
  "error": {
    "code": "validation_failed",
    "message": "The event does not match the canonical schema.",
    "request_id": "9c74068ce2044434b765d59669b5f294",
    "details": [
      {"index": null, "code": "validation_failed", "issues": ["authentication.src_port: ..."]}
    ]
  }
}
```

| Status | `code` | Meaning | Retry? |
|---|---|---|---|
| 400 | `invalid_json` | The body is not JSON | No, fix the client |
| 401 | `unauthorized` | Missing or unknown bearer token | No |
| 404 | `not_found` | Unknown path | No |
| 405 | `method_not_allowed` | Wrong method (see `Allow`) | No |
| 413 | `payload_too_large` | Body or single event too large | No, split or trim |
| 413 | `batch_too_large` | More than `API_MAX_BATCH_SIZE` events | No, split |
| 422 | `agent_mismatch` | An agent-bound client sent an event of another agent (or none) | No |
| 422 | `host_mismatch` | A client restricted by `API_INGEST_CLIENT_HOSTS` sent an event for another host (or none) | No |
| 415 | `unsupported_media_type` | Content-Type is not `application/json` | No |
| 422 | `validation_failed` | Not a canonical event, wrong batch shape, or no valid event | No, fix the events |
| 422 | `unsupported_schema_version` | Unknown `schema_version` | No, upgrade or downgrade the producer |
| 422 | `empty_batch` | `{"events": []}` | No |
| 429 | `rate_limited` | Client budget exhausted | Yes, after `Retry-After` |
| 500 | `internal_error` | Unexpected server failure | Yes, with backoff |
| 503 | `service_unavailable` | Kafka did not acknowledge in time, or is not connected yet | Yes, after `Retry-After` |

Every response, errors included, carries `X-Request-ID` and `X-Trace-ID`. A safe
client-supplied `X-Request-ID` is adopted.

A `503` is logged at `warning` with `error_type` and `reason` (the traceback only at
`debug`), so an outage does not flood the logs with stack traces.

## Metrics

`GET /metrics` serves, from a registry private to the application:

| Metric | Labels | Meaning |
|---|---|---|
| `adis_api_http_requests_total` | `method`, `route`, `status` | Requests handled. `route` is the route template (never the raw path), `unmatched` otherwise, so labels stay bounded. |
| `adis_api_http_request_duration_seconds` | `method`, `route` | Latency histogram. |
| `adis_api_events_total` | `outcome` (`accepted`, `rejected`) | Events submitted. |
| `adis_api_publish_failures_total` | | Publications Kafka did not acknowledge. |
| `adis_api_rate_limited_total` | | Requests refused with `429`. |
| `adis_api_rate_limit_fallbacks_total` | | Decisions taken in process because Redis failed. |

Each accepted event is also logged (`api_event_accepted`, with `event_id`, `trace_id`
and `host_id`) when `LOG_EVENT_LIFECYCLE=true`, so one event can be followed from the API
through the normalizer.

## Running locally

1. Start Kafka and create the topics (see [DEVELOPMENT.md](DEVELOPMENT.md#kafka)).
2. Set `API_INGEST_TOKENS` in `.env`:

   ```dotenv
   API_INGEST_TOKENS=agent-dev:<token from python -c "import secrets; print(secrets.token_urlsafe(32))">
   ```

   Optionally restrict a client to its hosts (required for `agent-<uuid>` clients outside
   development and test):

   ```dotenv
   API_INGEST_CLIENT_HOSTS=agent-dev=web-1
   ```

3. Run `make api` (or `python -m apps.api`). This serves on `API_HOST:API_PORT`
   (default `127.0.0.1:8000`) with JSON logs only.
4. Send an event:

   ```bash
   curl -sS -X POST http://127.0.0.1:8000/api/v1/events -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d '{"schema_version":"1.0","category":"authentication","event_type":"authentication.login","timestamp":"2026-09-25T12:00:00Z","source_type":"auditd","source_name":"auditd@web-1","host_id":"web-1","success":false,"username":"root","src_ip":"203.0.113.7"}'
   ```

## Tests

- **Unit tests** (`tests/unit/api`) run the application in-process with an in-memory
  publisher. They cover:
  - probes;
  - authentication;
  - validation and error codes;
  - body, event and batch limits;
  - rate limiting, in memory and in Redis (with the fallback);
  - agent-bound and host-bound tokens;
  - metrics, readiness with Redis, and the background Kafka connection;
  - provenance;
  - OpenAPI completeness, including that every `$ref` resolves.
- **Integration tests** (`tests/integration/api`, run when `TEST_KAFKA_BOOTSTRAP_SERVERS`
  is set) publish through the real application and read the records back from Kafka.
  `tests/integration/redis` (with `TEST_REDIS_URL`) checks the shared budget between
  two limiter instances and the fallback against a real Redis.
