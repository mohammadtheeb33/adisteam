# Phase 1 verification report

**Result: PASS.** Run `p1-20260926T121803-034a6c`, started 2026-09-26 12:18:03 UTC, took 85 s.

Flow under test: generator → ingestion API (HTTP) → Kafka (`adis.system.events`, `adis.auth.events`, `adis.network.events`) → normalizer → Kafka (`adis.security.events`) and PostgreSQL (`adis.security_events`). Every service ran as a real process against a real broker and database; outages were real container stops.

## Results

| Scenario | Sent | Accepted | Normalized | Stored | Duplicates | Failed | Dead-lettered | Latency p50 | Latency p95 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Single events (POST /api/v1/events) | 3 | 3 | 3 | 3 | 0 | 0 | 0 | 63 ms | 76 ms |
| Batches of 100 mixed events (POST /api/v1/events/batch) | 1000 | 1000 | 1000 | 1000 | 0 | 0 | 0 | 617 ms | 1093 ms |
| Invalid events and poison records | 18 | 7 | 7 | 7 | 0 | 8 | 3 | 31 ms | 31 ms |
| Duplicate submissions | 72 | 72 | 10 | 10 | 62 | 0 | 0 | 78 ms | 78 ms |
| Endpoint agent: registration, API outage, crash | 0 | 0 | 0 | 0 | 0 | 0 | 0 | n/a | n/a |
| Temporary database failure | 100 | 100 | 100 | 100 | 0 | 0 | 0 | 15.8 s | 16.0 s |
| Temporary Kafka failure | 100 | 100 | 100 | 100 | 0 | 0 | 0 | 26.4 s | 26.8 s |
| **Steady state** (first four) | **1093** | **1082** | **1020** | **1020** | **62** | **8** | **3** | 484 ms | 1093 ms |
| **All scenarios** | **1293** | **1282** | **1220** | **1220** | **62** | **8** | **3** | 813 ms | 26.4 s |

Latency is measured from the generator's first send attempt to the normalized event appearing on `adis.security.events` (both on the verifier's clock). For the outage scenarios it includes the outage itself. See [Definitions](#definitions).

### Acceptance latency (HTTP 202)

| Scenario | p50 | p95 |
|---|---:|---:|
| Single events (POST /api/v1/events) | 16 ms | 16 ms |
| Batches of 100 mixed events (POST /api/v1/events/batch) | 78 ms | 125 ms |
| Invalid events and poison records | 15 ms | 15 ms |
| Duplicate submissions | 16 ms | 16 ms |
| Endpoint agent: registration, API outage, crash | n/a | n/a |
| Temporary database failure | 39 ms | 46 ms |
| Temporary Kafka failure | 25.7 s | 25.7 s |

## Checks

### Single events (POST /api/v1/events) (passed)

- ✅ accepted: 3 of 3
- ✅ normalized to adis.security.events: 3 of 3
- ✅ stored exactly once: 3 of 3
- ✅ ingestion metadata stored: metadata.adis_ingestion = {'producer': 'adis-api', 'normalizer': 'adis-normalizer', 'request_id': 'baf9773045ab4b238405cb27780f3648', 'source_topic': 'adis.system.events', 'ingest_client': 'phase1-verifier', 'normalized_at': '2026-09-26T12:18:10.436264Z', 'source_offset': 2389, 'source_partition': 1}

### Batches of 100 mixed events (POST /api/v1/events/batch) (passed)

- ✅ accepted: 1000 of 1000
- ✅ normalized to adis.security.events: 1000 of 1000
- ✅ stored exactly once: 1000 of 1000
- ✅ every category delivered: categories: ['authentication', 'network', 'system']

### Invalid events and poison records (passed)

- ✅ invalid events rejected with 422 naming the field: 5 rejected
- ✅ partial batch: valid events accepted, invalid ones rejected by index: accepted 7, rejected indices [3, 6, 7]
- ✅ accepted: 7 of 7
- ✅ normalized to adis.security.events: 7 of 7
- ✅ stored exactly once: 7 of 7
- ✅ poison records dead-lettered by the normalizer: CanonicalEventError from adis.auth.events, CanonicalEventError from adis.network.events, DeserializationError from adis.network.events
- ✅ poison records never stored: none

### Duplicate submissions (passed)

- ✅ API accepted every duplicate (deduplication is the pipeline's job): 62 duplicate submissions
- ✅ duplicates created no database rows: rows per event: [1]
- ✅ already stored events were not published again: 0 re-published of 51
- ✅ duplicates inside one batch were published once: 10 of 10 published exactly once

### Endpoint agent: registration, API outage, crash (passed)

- ✅ agent kept its events and retried while the API was down: alive=True, 5 retries
- ✅ agent registered in adis.agents: name, status = ('phase1-agent', 'active')
- ✅ every log line stored exactly once: 120 rows, 120 event ids, 120 lines of 120 written
- ✅ events linked to the registered agent: 120 of 120
- ✅ last_seen advanced with the agent's telemetry: first_seen=2026-09-26 12:18:17.928685+00:00, last_seen=2026-09-26 12:18:37.046737+00:00
- Note: API process stopped
- Note: API restarted after 15 s; the agent logged 5 send retries meanwhile
- Note: agent killed 0.3 s after writing lines, then restarted
- Note: 120 log lines written and sent by the agent itself (the columns of the results table count the verifier's own submissions only)

### Temporary database failure (passed)

- ✅ API kept accepting while the database was down: 100 accepted
- ✅ normalizer retried instead of dead-lettering: 4 retries logged
- ✅ accepted: 100 of 100
- ✅ normalized to adis.security.events: 100 of 100
- ✅ stored exactly once: 100 of 100
- ✅ normalizer survived the outage: process running
- Note: database container 'adis-postgres-test-1' stopped
- Note: down for 15.5 s; healthy 5.1 s after the restart
- Note: the 100 queued events were normalized and stored within 0.6 s of the restart

### Temporary Kafka failure (passed)

- ✅ API reported not ready while Kafka was down: GET /ready -> 503
- ✅ clients were told to retry (503) instead of losing events: 16 retried requests: {'503': 16}
- ✅ every event accepted after recovery: 100 of 100
- ✅ accepted: 100 of 100
- ✅ normalized to adis.security.events: 100 of 100
- ✅ stored exactly once: 100 of 100
- ✅ API and normalizer survived the outage: api alive=True, normalizer alive=True
- Note: Kafka container 'adis-kafka-1' stopped
- Note: down for 18.9 s; healthy 8.6 s after the restart
- Note: all 100 events accepted, normalized and stored within 8.0 s of the restart

### Whole-run invariants (passed)

- ✅ no accepted event lost (stored): 0 missing of 1220
- ✅ no accepted event lost (normalized): 0 missing of 1220
- ✅ exactly one row per event: 0 events with != 1 row
- ✅ no valid event dead-lettered: 0 unexpected dead letters
- ✅ unique event_id enforced by the database: 0 duplicates

## Fault injection

- Retried API requests (status or transport error: count): `503` = 16
- Normalizer log actions during the run: `normalizer_batch_processed` = 28, `normalizer_retry` = 4, `normalizer_batch_isolated` = 0, `normalizer_record_dead_lettered` = 4, `kafka_commit_failed` = 0, `normalizer_unexpected_error` = 0

## Environment and settings

- python: `3.12.0`
- platform: `Windows-11-10.0.26200-SP0`
- postgresql: `17.11`
- kafka_bootstrap: `127.0.0.1:9092`
- kafka_container: `adis-kafka-1`
- database_container: `adis-postgres-test-1`
- Service settings (others at their defaults): `APP_ENV` = test, `LOG_LEVEL` = INFO, `API_MAX_BATCH_SIZE` = 500, `API_RATE_LIMIT_EVENTS` = 1000000, `API_PUBLISH_TIMEOUT_SECONDS` = 5, `NORMALIZER_CONSUMER_GROUP` = adis-normalizer, `NORMALIZER_POLL_TIMEOUT_MS` = 200, `NORMALIZER_RETRY_MAX_BACKOFF_SECONDS` = 5
- Batch scenario: 1000 events; outages: 100 events, 15 s down

## Definitions

- **Sent**: events submitted to the API (including duplicates and invalid events) plus records written straight to Kafka.
- **Accepted**: submissions the API accepted (202).
- **Normalized**: distinct first-time events seen on `adis.security.events`.
- **Stored**: distinct first-time events with a row in `adis.security_events`.
- **Duplicates**: accepted re-submissions of an event already submitted; they must create no row and no publication.
- **Failed**: submissions the API rejected (4xx) or never accepted.
- **Dead-lettered**: records of the scenario found on `adis.deadletter`.

Reproduce with `make verify-phase1` (see [VERIFICATION.md](VERIFICATION.md)).
