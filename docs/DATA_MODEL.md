# Phase 1 database

`adis.agents` stores registered collector identities and lifecycle timestamps.
`adis.security_events` stores canonical collected telemetry, agent/host references and query fields.
`adis.alembic_version` records revision `5b8e2c4f1a93`.

Only the two original Phase 1 migrations are included. `database/schema-phase1.sql`
is the complete application DDL for these tables, indexes, constraints and RLS.
No model registry, features, anomaly results, threats, immune memory or response tables are included.
Actual source PostgreSQL records remain unavailable: see `START_HERE_AR.md`.
