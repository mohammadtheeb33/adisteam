"""Phase 1 end-to-end verification.

Drives the real pipeline, generator → ingestion API → Kafka → normalizer → Kafka and
PostgreSQL, through six scenarios (single, batch, invalid, duplicate, database outage,
Kafka outage), checks every guarantee, and writes a report. Run it with
``python -m tests.e2e.phase1`` (see docs/VERIFICATION.md).
"""
