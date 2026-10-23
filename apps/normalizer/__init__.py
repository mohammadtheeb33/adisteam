"""Normalization pipeline: accepted telemetry to canonical, deduplicated, stored events.

Consumes ``system_logs``, ``auth_events`` and ``network_flows``,
normalizes every record to the canonical event schema, stores it in Supabase PostgreSQL
and publishes it to ``adis.security.events``. See docs/NORMALIZER.md.
"""
