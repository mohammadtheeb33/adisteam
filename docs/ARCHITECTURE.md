# Phase 1 architecture

Scope: pentra.pdf section 2, pages 4-5: sensing and data collection.

Agent collectors -> FastAPI -> Kafka raw topics -> normalizer -> PostgreSQL and normalized Kafka events.

- Raw topics: `system_logs`, `auth_events`, `network_flows`.
- Output: `adis.security.events`; processing failures: `adis.deadletter`.
- Sources: Syslog, Windows Event Log, NetFlow/IPFIX, PCAP, auditd/eBPF, authentication/access logs and session vectors.
- Collection, durable buffering, validation, normalization, deduplication, storage and ingestion metrics belong here.
- Anomaly algorithms, detector feature generation, model training, score fusion, immune learning and responses belong to later phases.
- Redis supports the ingestion rate limiter; it does not store immune memory in this copy.

The current primary project's collector implementations are preserved; shared package interfaces are narrowed to this scope.
