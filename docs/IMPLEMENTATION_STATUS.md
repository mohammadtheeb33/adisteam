# Phase 1 extracted copy status

Updated 2026-10-23. Scope: pentra.pdf section 2, pages 4-5.
Only the collector agent, ingestion API, normalizer and six ingestion support packages remain.
The existing Phase 1 collector behavior is retained from the current primary project; shared configuration,
database registration, Kafka catalogue, deployment, dependencies and tests are narrowed to Phase 1.

Validation: 1665 passed, 67 skipped (65 require service configuration/opt-in E2E; 2 POSIX permissions).
Ruff lint and format checks pass. Strict mypy passes in 208 files. Wheel build and Compose validation pass.
The local import closure is complete, and the ORM registers only agents and security_events.
The historical 17/19 score belongs to the source report, not a new performance evaluation of this extraction.
PostgreSQL rows have not been exported; the complete Phase 1 migration schema and original local evidence are included.

Second audit: 101 local modules imported independently from the built wheel; Docker build and bind sources all present. See ../PHASE1_FILE_AUDIT_AR.md.
