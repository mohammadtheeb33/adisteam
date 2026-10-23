# تقرير معالجة نتائج تدقيق المرحلتين 0 و1 وإعادة الاختبار

- **التاريخ:** 2026-09-26
- **المرجع:** [PHASE_0_1_AUDIT.md](PHASE_0_1_AUDIT.md) (22 نتيجة: 0 CRITICAL، و4 HIGH، و9 MEDIUM، و9 LOW)
- **النطاق:** إصلاح كل النتائج، ثم إعادة تشغيل كل الاختبارات وفحوص التدقيق التشغيلية على خدمات حقيقية.

## 1. الخلاصة

| المرحلة | قبل (التدقيق) | بعد (هذا التقرير) |
|---|---|---|
| المرحلة 0: أساس المستودع | PARTIAL | **PASS**. بقي أول تشغيل لـCI على GitHub، وهو يحتاج remote وأول commit من المالك |
| المرحلة 1: الأساسات ومسار الاستقبال | PARTIAL | **PASS** على PostgreSQL 17، وعلى صورة Supabase Postgres 17.6، وعلى مشروع Supabase المستضاف (تحديث 26 سبتمبر) |

- **النتائج:** أُصلحت 21 نتيجة من 22 بالكامل.
- **نتيجة واحدة جزئية بقرار:** 014، إذ تبقى الطوابع القديمة والمنفذ 0 مقبولة عمداً.
- **نتائج جديدة ظهرت أثناء الإصلاح:** عشر نتائج، أُصلح منها ثمانٍ ووُثّقت اثنتان (§4).
- **النتائج العالية (HIGH):** كلها مغلقة. آخرها 004 بعد التحقق على مشروع Supabase المستضاف.

**التوصية:** لا يوجد بند قبول مفتوح في المرحلتين 0 و1. قبل بدء المرحلة 2 يُنصح بأول commit ودفع المستودع ليعمل الـCI (§5).

## 2. حالة كل نتيجة

| المعرّف | الخطورة | الحالة | ما الذي تغيّر | الدليل |
|---|---|---|---|---|
| 001 | HIGH | ✅ مُصلح | الحزمة `packages/redis`: عميل بـnamespaces، وTTL إلزامي، ونوافذ عدّ ذرية (Lua)، ومهل اتصال، وإعادة اتصال، وفحص صحة لا يرمي، وإغلاق. محدِّد معدل مشترك عبر Redis في الـAPI (`API_RATE_LIMIT_BACKEND=redis`) مع رجوع للذاكرة، وفحص Redis في `/ready` | 15 اختبار وحدة و7 اختبارات تكامل على Redis حقيقي (`tests/integration/redis`) |
| 002 | HIGH | ✅ مُصلح | الاختبارات تلتقط إزاحات النهاية قبل الإنتاج وتقرأ منها فقط. المستهلك يثبّت الإزاحات مرة لكل partition في كل poll | الاختبار الفاشل سابقاً ينجح، ولم تعد مدته مرتبطة بحجم الوسيط. حزمة التكامل (59 اختباراً) صارت 58 ث بعد أن كانت 210 ث لـ37 اختباراً، وذلك مع إصلاح N1 |
| 003 | HIGH | ✅ مُصلح | `git init` بلا commits حسب طلبك، و`.gitattributes`، و`.github/workflows/ci.yml` بثلاث مهام. `ADIS_REQUIRE_SERVICES=1` يحوّل كل تخطٍّ بسبب خدمة غائبة إلى فشل (`tests/services.py`) | لم يُشغَّل الـCI على GitHub بعد (لا remote) |
| 004 | HIGH | ✅ مُصلح | خدمة `supabase-db-test` (الصورة `supabase/postgres:17.6.1.177`، profile `supabase-test`)، واختبارات تثبت أن `anon` و`authenticated` لا يصلان إلى `adis.*`. ثم على مشروع المالك المستضاف: طُبّقت الترحيلات عبر Supavisor (session pooler) مع `DB_SSL_MODE=require` | على الصورة: 59 نجاح و0 تخطٍّ. على المشروع المستضاف: حزمة القاعدة ناجحة في وضعي الجلسة (5432) والمعاملات (6543)، بعد تصحيح توقع واحد يخص سلوك Supavisor (N8). واختبارات الـNormalizer ناجحة. مستشار الأمان في Supabase لا يُظهر إلا ملاحظة «RLS بلا سياسات» المقصودة |
| 005 | MEDIUM | ✅ مُصلح | سجل لكل حدث في الـAPI (`api_event_accepted`) وفي الـnormalizer (`normalizer_event_stored` أو `normalizer_event_duplicate`)، مع `event_id` و`trace_id` و`host_id`. سجلات DLQ داخل `log_context` بمعرّفات الحدث حين تُقرأ. المفتاح `LOG_EVENT_LIFECYCLE` | اختبارات وحدة في `tests/unit/normalizer/test_remediation.py` و`tests/unit/api/test_resilience.py` |
| 006 | MEDIUM | ✅ مُصلح | الـnormalizer يحدّث `adis.agents` من أحداث `system.agent_registered` داخل معاملة الدفعة. `first_seen` و`last_seen` لا يرجعان للخلف، وحالة `decommissioned` تُحفظ. `last_seen` يتقدم مع كل قياس عن بُعد | 6 اختبارات تكامل للسجل واختبار تكامل للـnormalizer. سيناريو e2e للوكيل: 120 من 120 حدثاً مربوطة بصف الوكيل. فحص الوكيل: 849 صفاً مربوطاً بعد أن كانت 0 |
| 007 | MEDIUM | ✅ مُصلح | الـAPI يتصل بـKafka في الخلفية مع إعادة المحاولة (503 حتى الاتصال). الـnormalizer ومستهلك الدفعات يعيدان محاولة الاتصال. `producer.start()` يغلق العميل عند الفشل، فلا تحذير `Unclosed AIOKafkaProducer`. Dockerfile بمستخدم غير root، وprofile `app` بـ`restart: unless-stopped` وhealth checks | فحص الإقلاع: الـAPI والـnormalizer حيّان بعد 25 ث وKafka متوقف (سابقاً: خروج فوري). الحاوية أُعيد تشغيلها بعد SIGTERM (`RestartCount=1`، healthy) |
| 008 | MEDIUM | ✅ مُصلح | مقاييس Prometheus في الـAPI (`/metrics`) والـnormalizer (`/health` و`/ready` و`/metrics` على listener خفيف). `PROMETHEUS_ENABLED` موصول. أهداف scrape للـAPI والـnormalizer. `/ready` في الـnormalizer يفحص القاعدة | اختبار تكامل للنقاط الثلاث، وتحقق داخل الحاويات. حاوية Prometheus نفسها لم تُشغَّل (§5) |
| 009 | MEDIUM | ✅ مُصلح | `KafkaConsumer` المشترك يثبّت مرة لكل partition في كل poll، ويعيد الأعطال العابرة (انقطاع) بلا حد بدل DLQ، ويعالج `CommitFailedError` و`IllegalStateError`، ويسجل الـrebalance | اختبارات وحدة جديدة في `tests/unit/kafka` |
| 010 | MEDIUM | ✅ مُصلح | `Spool.open()` يشغّل `quick_check`. الملف التالف يُنقل إلى `spool.sqlite3.corrupt-<وقت>` مع ملفات WAL، ويُنشأ spool جديد، ويُسجَّل `agent_spool_corrupt` | اختبار وحدة لملف تالف |
| 011 | MEDIUM | ✅ مُصلح | SASL: ‏PLAIN وSCRAM-SHA-256/512، مع `KAFKA_SASL_*` وكلمة المرور `SecretStr`. الإنتاج يرفض Kafka بلا TLS، ويرفض `DB_SSL_MODE` غير `require` و`verify-ca` و`verify-full` | اختبارات إعدادات جديدة |
| 012 | MEDIUM | ✅ مُصلح | مجموعات الاختبار تبدأ من نهاية المواضيع (`commit_group_offsets`)، فلا تعيد قراءة التاريخ ولا تعيد نشره. `TRUNCATE` باقٍ لأنه على قاعدة اختبار مؤقتة | زمن كل اختبار normalizer بين 3.6 و6 ث، مع أن الوسيط يحمل عشرات آلاف السجلات من تشغيلات سابقة |
| 013 | MEDIUM | ✅ مُصلح | تكرار `event_id` بمحتوى مختلف يذهب إلى DLQ كـ`ConflictingDuplicateError` ويُعدّ، والحدث المخزن لا يتغير. الرموز ذات المعرّف `agent-<uuid>` مربوطة بوكيلها، وغيرها يُرفض بـ`422 agent_mismatch` | اختبار تكامل للتعارض، واختبار e2e برمز مربوط بالوكيل |
| 014 | LOW | ⚠️ جزئي (بقرار) | الطابع المستقبلي أبعد من `NORMALIZER_MAX_FUTURE_SKEW_SECONDS` (300 ث افتراضياً) يُحفظ ويُعلَّم (`timestamp_skew_seconds`، وسجل، ومقياس). الطوابع القديمة والمنفذ 0 مقبولة عمداً: إعادة تشغيل مجموعات بيانات تاريخية، والمنفذ 0 يظهر في سجلات تدفق حقيقية | فحص الحواف: حدث +365 يوماً خُزّن بعلامة `31535999.966` ثانية |
| 015 | LOW | ✅ مُصلح | علامة الإيقاف تُمسح عند انتهاء `run()` لا عند بدئه | اختبارات «إيقاف قبل التشغيل» للمستهلكين |
| 016 | LOW | ✅ مُصلح | حُذف `CLAUDE.txt`. الحزم الفارغة موسومة placeholder في docstrings، مع المرحلة التي ستُنفذ فيها. إعدادات Supabase وAuth وModelStorage و`DRY_RUN` محجوزة للمراحل اللاحقة وموثقة. Redis و`PROMETHEUS_ENABLED` صارا موصولين | — |
| 017 | LOW | ✅ مُصلح | README وIMPLEMENTATION_STATUS يعكسان نتيجة التدقيق والمعالجة. مثال docstring في `packages/config` صُحّح. جدول البنية المحلية يشمل كل الخدمات والـprofiles. أُضيف دليل «Run the pipeline locally» | `docs/DEVELOPMENT.md` |
| 018 | LOW | ✅ مُصلح | `API_MAX_CONCURRENT_REQUESTS` (256) عبر `limit_concurrency` في uvicorn، والمحدِّد المشترك عبر Redis (001) | اختبار وحدة لقيمة `limit_concurrency` |
| 019 | LOW | ✅ مُصلح | الرد 503 يُسجَّل على مستوى warning مع `error_type` و`reason`، والـtraceback على مستوى debug فقط | `tests/unit/api/test_resilience.py` |
| 020 | LOW | ✅ مُصلح | Keyset pagination عبر `EventCursor` على `(timestamp, id)` في الاتجاهين | 3 اختبارات تكامل على 2500 حدث، مع طوابع متكررة وإدراج أثناء القراءة |
| 021 | LOW | ✅ مُصلح | كلمة مرور Redis في ملف إعداد خاص (`0600`، مالكه `redis`)، لا في سطر الأوامر ولا في بيئة الخادم. كل خدمة تفحص سرّها عند الإقلاع بدل `${VAR:?}`، وGrafana يرفض الإقلاع بلا كلمة مرور بدل الرجوع إلى admin | `ps` داخل الحاوية يُظهر `redis-server *:6379` كمستخدم `redis`. عدد مرات ظهور `REDIS_PASSWORD` في بيئة العملية: 0. `docker compose config` صالح بلا `.env` |
| 022 | LOW | ✅ مُصلح | مجلد بيانات الوكيل على Windows يُقيَّد بـ`icacls`. والـspool مشفر بـAES-256-GCM: المفتاح محمي بـDPAPI على Windows، وبملف `0600` على POSIX، أو يُمرَّر عبر `AGENT_SPOOL_KEY`. والمخزن الذي لا يفتحه المفتاح يُنقل جانباً | 21 اختبار وحدة للتشفير (منها DPAPI فعلي على Windows)، واختبارات إعدادات للمفتاح |

## 3. إعادة الاختبار

بيئة التشغيل: Windows 11، وPython 3.12.0، وDocker Compose v5.1. وسيط Kafka 3.9.1 حقيقي، وPostgreSQL 17 (`postgres-test`)، وSupabase Postgres 17.6 (`supabase-db-test`)، وRedis 7.4. كلمات المرور مولَّدة عشوائياً في ملف مؤقت خارج المستودع.

| الفحص | الأمر | قبل | بعد |
|---|---|---|---|
| Lint | `ruff check .` و`ruff format --check .` | نظيف (172 ملفاً) | **نظيف** (207 ملفات) |
| الأنواع | `mypy` (strict) | نظيف | **نظيف** (192 ملفاً) |
| الوحدة | `pytest tests/unit` | 1327 نجاح، 1 تخطٍّ | **1448 نجاح، 1 تخطٍّ** (فحص صلاحيات POSIX على Windows) |
| التكامل على PostgreSQL | `ADIS_REQUIRE_SERVICES=1 pytest tests/integration` | 37 نجاح، واختبار يفشل حسب حجم الوسيط | **56 نجاح، 3 تخطٍّ**: اختبارات أدوار Supabase، ولا تنطبق على PostgreSQL العادي. المدة 58 ث |
| التكامل على Supabase Postgres | `TEST_DATABASE_IS_SUPABASE=1 pytest tests/integration` | لم يُنفَّذ | **59 نجاح، 0 تخطٍّ** |
| القاعدة بوضع transaction pooler | `DB_TRANSACTION_POOLER=true pytest tests/integration/database` على Supabase | لم يُنفَّذ | **40 نجاح** |
| E2E | `TEST_E2E=1 pytest tests/e2e` | نجاح (6 سيناريوهات) | **نجاح** (7 سيناريوهات، منها الوكيل الحقيقي) |
| التحقق الكامل | `python -m tests.e2e.phase1 --batch-events 1000` | — | **PASS: 42 فحصاً من 42** ([التقرير](PHASE1_VERIFICATION_REPORT.md)) |
| فحوص التدقيق التشغيلية | `edge` و`crash` و`agent` و`startup` و`shutdown` | الإقلاع يفشل بلا Kafka؛ `agents` فارغ | انظر أدناه |

**نتائج التحقق الكامل (1000 حدث في الدفعات):**
- **الأحداث:** 1220 حدثاً مقبولاً. كلها طُبّعت وخُزنت مرة واحدة، ولم يُرسل حدث صالح إلى DLQ.
- **الزمن:** p95 في الحالة المستقرة 1093 ms.
- **انقطاع القاعدة:** خُزّنت الأحداث خلال 0.6 ث من عودتها.
- **انقطاع Kafka:** خُزّنت كل الأحداث خلال 8 ث من عودته.
- **سيناريو الوكيل:**
  - المسار: عملية `apps.agent` حقيقية برمز مربوط بها، وانقطاع للـAPI مدته 15 ث، ثم قتل الوكيل قسراً وإعادة تشغيله.
  - النتيجة: 120 سطراً مكتوباً، منها 120 حدثاً مخزناً بمعرّفات فريدة، و120 مربوطة بصف الوكيل.
  - أثناء الانقطاع سجّل الوكيل 5 إعادات إرسال.

**فحوص التدقيق التشغيلية:**
- `startup`:
  - مع توقف Kafka: الـAPI والـnormalizer حيّان بعد 25 ث ويعيدان المحاولة.
  - مع توقف القاعدة عند الإقلاع: قُبلت 20 من 20، وخُزنت 20 بعد العودة.
- `crash`:
  - قُتل الـnormalizer بعد تخزين 168 من 1000 حدث.
  - بعد إعادة التشغيل خُزنت 1000 مختلفة خلال 11.7 ث، بصف واحد لكل حدث، و1000 منشورة بلا نشر زائد.
- `agent`:
  - المجموع 600 سطراً و600 صفاً، ولا تكرار.
  - صف التسجيل موجود في `adis.agents`.
- `edge`: الحالات الـ27 كما هو متوقع (202 أو 4xx مع اسم الحقل). فحص التتبع يعيد `trace_id` في الرد، والطابع المستقبلي مُعلَّم.
- `shutdown`:
  - توقف الـnormalizer في 0.19 ث.
  - 0 سجلات أُعيدت معالجتها بعد إعادة تشغيل نظيفة، وتوقف الـAPI بنظافة.

**حاويات profile `app`:**
- بناء الصورة من `python:3.12-slim`؛ حجمها 302MB.
- تعمل بالمستخدم `adis` (uid 10001)، بنظام ملفات للقراءة فقط، وبلا capabilities.
- حدث عبر الـAPI خُزّن في القاعدة.
- `/ready` للخدمتين 200.
- بعد SIGTERM للـnormalizer: إيقاف نظيف، ثم إعادة تشغيل تلقائية وحالة healthy.

## 4. نتائج جديدة ظهرت أثناء الإصلاح

| # | الخطورة | النتيجة | الحالة |
|---|---|---|---|
| N1 | MEDIUM | Kafka يعلن `localhost` بينما المنفذ مربوط بـ127.0.0.1 فقط. على Windows يُجرَّب `::1` أولاً، فتكلّف كل محاولة اتصال ثانيتين (قيس: 4.1 ث لكل عميل) | ✅ يعلن الآن `KAFKA_ADVERTISED_HOST` (افتراضياً 127.0.0.1): 0.02 ث لكل عميل. حزمة التكامل صارت 58 ث بعد أن كانت 486 ث |
| N2 | MEDIUM | أثناء انقطاع Redis كان كل طلب ينتظر مهلة الاتصال وإعاداتها (حتى نحو 6 ث) قبل الرجوع للذاكرة | ✅ بعد أي فشل يتجاوز المحدِّد Redis لمدة 5 ث (الثابت `REDIS_RETRY_INTERVAL_SECONDS` في `apps/api/rate_limit.py`، قابل للتغيير عبر المُنشئ)، مع اختبار وحدة |
| N3 | LOW | حاوية Redis السابقة كانت تعمل كـroot، لأن `sh -c` تجاوز إسقاط الصلاحيات في الـentrypoint | ✅ صار الـexec عبر `docker-entrypoint.sh`، فالعملية تعمل كمستخدم `redis` |
| N4 | LOW | إزالة `${VAR:?}` كانت ستجعل Grafana يعمل بكلمة المرور الافتراضية admin | ✅ فحص صريح عند الإقلاع يرفض كلمة المرور الفارغة |
| N5 | LOW | أداة الاختبار `read_from` كانت تنتهي بعد ثلاث قراءات فارغة، فتفشل إن تأخر بدء الجلب | ✅ تقرأ حتى إزاحات النهاية الملتقطة مع مهلة |
| N6 | LOW | الجدول `adis.alembic_version` بلا RLS، وصنّفه مستشار Supabase «حرجاً» | ✅ ترحيل `5b8e2c4f1a93` يفعّل RLS عليه، بموافقة المالك. طُبّق على المشروع المستضاف، واختفى التحذير |
| N7 | MEDIUM | خادم الصحة في الـNormalizer كان يغلق الاتصال دون رد إذا تجاوز فحص الجاهزية 5 ثوانٍ. ظهر مع قاعدة بعيدة (نحو 320 ms للذهاب والإياب) | ✅ مهلة قراءة الطلب منفصلة عن مهلة الفحص، ومهلة الفحص = مهلة فحص القاعدة + ثانيتان، والتجاوز يُرد عليه بـ503 صريح. مع اختبارات وحدة |
| N8 | INFO | Supavisor يستبدل `application_name` بـ`Supavisor`، فلا تظهر أسماء خدمات ADIS في `pg_stat_activity` | موثّق في DEVELOPMENT.md، والاختبار يتوقع ذلك خلف المجمّع |
| N9 | LOW | كلمة مرور قاعدة البيانات التي فيها `@` غير مرمّز كانت تظهر كخطأ DNS مضلل | ✅ الإعدادات ترفضها عند الإقلاع برسالة تطلب `%40`، دون طباعة القيمة |
| N10 | LOW | الاتصال المباشر بالمشروع المستضاف عبر IPv6 فقط، ولا يعمل على شبكات IPv4 | موثّق: استخدام session pooler مع مهل اتصال أطول للمناطق البعيدة |

## 5. البنود المتبقية

1. **أول commit وتشغيل الـCI:** المستودع مهيّأ بلا commits حسب طلبك. سيعمل الـCI عند الدفع إلى GitHub.
2. **Prometheus وGrafana (أُغلق):** شُغّلا فعلياً. الهدفان `adis-api` و`adis-normalizer` في حالة `up`، ولوحة «ADIS ingestion pipeline» مجهزة تلقائياً وأظهرت 12 من 13 لوحة عرض بيانات حقيقية. قواعد التنبيه ما زالت للمرحلة 6.
3. **كلمة مرور قاعدة البيانات المستضافة:** ظهرت في المحادثة أثناء الإعداد، ويُنصح بتغييرها من لوحة Supabase.
4. **المحدِّد عبر Redis نافذة ثابتة:** يسمح بدفعة تصل إلى ضعف الميزانية عند حدود النافذة. GCRA أنعم (OD-17).
5. **قرارات معمارية خارج نطاق المرحلة 1، بلا تغيير:**
   - OD-6: allowlist المختبر، ويبقى `DRY_RUN=true`.
   - OD-11: دور `adis_app`.
   - OD-13: أداة إعادة تشغيل DLQ.
   - OD-14: OpenTelemetry.
   - OD-15: مهمة الاحتفاظ.
6. **GNU make غير مثبت** على هذا الجهاز، فشُغّلت الأوامر المكافئة مباشرة.

## 6. التنزيلات أثناء المعالجة (بموافقتك)

- **حزم PyPI:** `redis` 8.1.0، و`prometheus-client` 0.26.0، و`cryptography` 46.0.7 (مع `cffi` و`pycparser`).
- **صور Docker:** `redis:7.4-alpine`، و`supabase/postgres:17.6.1.177`، و`python:3.12-slim`، و`prom/prometheus:v3.5.0`، و`grafana/grafana:12.1.1`.
- **بناء صورة التطبيق:** ثبّت اعتماديات `pyproject.toml` نفسها من PyPI داخل الصورة.

## 7. الملفات الرئيسية المتغيرة

- **حزم جديدة:**
  - `packages/redis`
  - `packages/observability/metrics.py` و`health_server.py`
  - `packages/database/errors.py`
  - `packages/kafka/rebalance.py`
  - `packages/events/agents.py`
  - `apps/api/metrics.py` و`routes/metrics.py`
  - `apps/normalizer/metrics.py`
- **تعديلات:**
  - `packages/config`: SASL، وTLS في الإنتاج، وRedis، والإعدادات الجديدة.
  - `packages/kafka`: المستهلكان، والـproducer، والعملاء.
  - `packages/database/repositories`: سجل الوكلاء، و`EventCursor`، و`find_payloads`.
  - `apps/api`: الـpublisher، والمحدِّد، والمصادقة، والمسارات، والتطبيق.
  - `apps/normalizer`: الـpipeline، والخدمة، والتخزين، والتطبيع.
  - `apps/agent`: الـspool، والهوية، والتسجيل.
- **البنية:**
  - `docker-compose.yml`
  - `infrastructure/docker/Dockerfile`
  - `.dockerignore` و`.gitattributes`
  - `.github/workflows/ci.yml`
  - `infrastructure/prometheus/prometheus.yml`
  - `Makefile` و`.env.example`
- **الاختبارات:**
  - `tests/services.py`
  - `tests/integration/redis`
  - `tests/integration/database/test_agent_registry.py` و`test_event_pagination.py` و`test_supabase_roles.py`
  - اختبارات الـnormalizer الجديدة
  - عزل اختبارات Kafka
  - سيناريو الوكيل في `tests/e2e/phase1`
  - اختبارات وحدة جديدة لكل ما سبق
- **التوثيق:**
  - README، وARCHITECTURE (حالات OD)، وAPI، وNORMALIZER، وAGENT
  - DATA_MODEL، وEVENT_SCHEMA، وDEVELOPMENT، وVERIFICATION
  - IMPLEMENTATION_STATUS
  - PHASE1_VERIFICATION_REPORT (أُعيد توليده)
