# ADIS — Phase 1

المرحلة الأولى فقط: الاستشعار وجمع البيانات وتوحيدها واستقبالها عبر FastAPI ونقلها عبر Kafka وتخزين الأحداث.
مستخرجة من النسخة الأساسية الموثقة بنتيجة 17/19 وفق القسم الثاني من `pentra.pdf`، الصفحتين 4–5.

## Scope

- Applications: `apps/agent`, `apps/api`, `apps/normalizer`.
- Shared packages: `config`, `database`, `events`, `kafka`, `observability`, `redis`.
- Sources: Windows Event Log, Syslog, NetFlow/IPFIX, PCAP/live capture, auditd/eBPF and authentication session vectors.
- Raw topics: `system_logs`, `network_flows`, `auth_events`.
- Normalized events: `adis.security.events`; processing failures: `adis.deadletter`.
- Database: `agents`, `security_events`, plus `alembic_version`. Migration head: `5b8e2c4f1a93`.
- Complete Phase 1 application DDL: [`database/schema-phase1.sql`](database/schema-phase1.sql).

## Local setup

Requires Python 3.12. From the repository root on Windows:

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install --upgrade "pip>=25.1"
.venv\Scripts\python.exe -m pip install -e . --group dev
Copy-Item .env.example .env
.venv\Scripts\python.exe -m pytest -q
```

On Linux/macOS, use `.venv/bin/python` in place of `.venv\Scripts\python.exe`.
Configure `.env` before starting services. See [development commands](docs/DEVELOPMENT.md),
[architecture](docs/ARCHITECTURE.md) and [the file audit](PHASE1_FILE_AUDIT_AR.md).
The self-contained real-data lab is in `infrastructure/lab/` and `scripts/lab_phase1.py`.

## Verification and data

The extracted workspace passed **1665 tests**, with **67 skipped** because external services/E2E
were not configured or POSIX permissions were unavailable on Windows. Ruff, mypy, wheel build,
Docker Compose validation and isolated imports of 101 runtime modules passed.
The full live stack and performance targets were not re-evaluated during extraction;
17/19 is the historical source score.

This repository includes the database code and complete Phase 1 schema. **It does not include
a dump of the original PostgreSQL records.** Credentials, `.env`, local SQLite queues, encryption
keys, raw lab logs and local-only provenance files are excluded. `.env.example` is the setup template.
Historical reports describe evidence retained in the original local workspace; their raw local
artifacts are not part of this GitHub publication.
