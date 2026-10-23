# ADIS Phase 0–1 Audit — تدقيق المرحلتين 0 و1

> **تحديث 2026-09-26:** عولجت النتائج وأُعيد الاختبار. الحالة الحالية لكل نتيجة في [PHASE_0_1_REMEDIATION.md](PHASE_0_1_REMEDIATION.md). هذا التقرير محفوظ كما كُتب وقت التدقيق.
>
> **تحديث 2026-09-30 (إعادة فحص بعد المراحل 2 و3):** أُعيد فحص المشروع كاملاً على خدمات حقيقية، والتفاصيل والأرقام في [AUDIT_FOLLOW_UP_REPORT.md](AUDIT_FOLLOW_UP_REPORT.md). ما يخص هذا التدقيق:
>
> - **المسار يعمل مع الطبقتين التاليتين.** مسار الاستقبال (API ← Kafka ← normalizer ← PostgreSQL) يغذّي الآن الكشف والمناعة كسلسلة واحدة، ويثبت ذلك اختبار e2e جديد (`tests/e2e/test_full_chain.py`) تدخل فيه الأحداث عبر HTTP فقط.
> - **النتيجة 003 (CI):** كان يُقال إن CI معرَّف ولم يعمل بعد. تبيّن عند أول تشغيل على GitHub (2026-09-29) أن وظيفتي الخدمات فشلتا قبل أي اختبار، بسبب كتابة الأمر `::add-mask::` داخل ملف `$GITHUB_ENV` (صيغة غير صالحة)، فلم يُشغَّل في CI أي اختبار تكامل أو e2e قط. أُصلح ذلك في 2026-09-30، مع خطأ كامن ثانٍ (غياب `TEST_REDIS_URL` في خطوة e2e). **لم يُتحقق من التشغيل الأخضر بعد**: يحتاج دفعاً إلى GitHub.
> - **النتيجة 004 (Supabase الفعلي):** طُبّقت على المشروع المستضاف ترحيلات المراحل 2 و3 (الرأس `9c4e2b7a1d35`)، وشُغّل عليه خط المعالجة كاملاً (استقبال ← كشف ← مناعة) لقياس الأداء. المسار صحيح وظيفياً، لكنه أبطأ بكثير من القاعدة المحلية (نحو 0.16 حدث/ث مقابل 14)، بما يتوافق مع أنه محكوم بزمن رحلة القاعدة من جهاز التطوير (§ الأداء في تقرير المتابعة).
> - **ثغرة لم يلتقطها هذا التدقيق:** الرمز المربوط بوكيل (`agent-<uuid>`) كان يقيّد `agent_id` ولا يقيّد `host_id`، فيستطيع كتابة قياسات أي مضيف. أُغلقت في 2026-09-30 بالإعداد `API_INGEST_CLIENT_HOSTS` (القرار OD-34).
>
> حكم التقرير أدناه («PARTIAL» و«جاهز للمرحلة 2: NO») هو حكم وقت التدقيق ولم يُغيَّر، لأن التقرير دليل على حالة المشروع حينها.

- **تاريخ التدقيق:** 2026-09-25
- **وضع التدقيق:** قراءة وتشغيل فقط. لم يُعدَّل أي ملف في الكود أثناء التدقيق. الملف الوحيد المُنشأ هو هذا التقرير.
- **بيئة التشغيل:**
  - Windows 11 (10.0.26200)، Python 3.12.0، Docker 29.3.1؛
  - Kafka 3.9.1 (`apache/kafka:3.9.1`)؛
  - PostgreSQL 17.11 (`postgres:17-alpine`، ملف compose `test`).
- **قاعدة الأدلة:** كل حالة في التقرير مبنية على الكود الفعلي، أو على تشغيل فعلي على خدمات حقيقية، مع ذكر الملف والسطر أو الأمر المستخدم. لم يُعتمد على ادعاءات الوثائق.
- **سكربتات فحص إضافية:** مؤقتة، خارج المستودع (`audit_runtime.py`: edge وcrash وagent وstartup وshutdown). مخرجاتها في `.verification/audit-*/`، وهو مجلد مُستثنى من git.

---

## 1. Executive Summary — الملخص التنفيذي

| البند | الحالة |
|---|---|
| **الحالة العامة** | **PARTIAL** |
| المرحلة 0 | **PARTIAL**: الخطوة 0.4 (Redis) غير منفذة إطلاقاً (FAIL) |
| المرحلة 1 | **PARTIAL**: المسار يعمل ومتين، لكن بنوداً حرجة من معايير القبول غير مكتملة التحقق |
| المسار من طرف إلى طرف | **PASS** على PostgreSQL 17 وKafka حقيقيين؛ Supabase الفعلي **UNVERIFIED** |
| نتائج بدرجة CRITICAL | **0** |
| جاهز للمرحلة 2؟ | **NO** |

### الخلاصة

**ما يعمل فعلاً:** مسار الاستيعاب (agent/generator → FastAPI → Kafka → normalizer → Kafka → PostgreSQL) يعمل بشكل صحيح وموثوق. هذا مُثبت بتشغيل حقيقي:
- 1293 حدثاً في التحقق الكامل، و1000 حدث في اختبار انهيار قسري، و600 حدث من الوكيل الحقيقي مع انقطاع الـAPI وقتل الوكيل؛
- لا فقدان صامت للأحداث؛
- لا صفوف مكررة، بفضل قيد `UNIQUE (event_id)` مع `ON CONFLICT DO NOTHING`؛
- لا قبول كاذب عند انقطاع Kafka (ترجع 503)؛
- الإزاحات (offsets) لا تُثبَّت إلا بعد المعالجة.

**لماذا لا يمكن اعتبار المرحلة 1 مكتملة (COMPLETE):**
1. خطوة Redis (0.4) غير موجودة: لا عميل، ولا فحص صحة (health check)، ولا أي استخدام.
2. حزمة الاختبارات ليست خضراء. في تشغيل التدقيق الكامل **فشل اختبار تكامل واحد**:
   - الاختبار هو `test_published_event_is_consumed_and_committed`، وفشل مرتين في تشغيلين مختلفين.
   - سببه أن الاختبار يعتمد على كمية البيانات في الموضوع (topic).
   - ويكشف أن `KafkaConsumer` يثبّت الإزاحة بعد كل سجل منفرد، وهو بطيء (328 سجل/ث).
3. الاختبارات الحرجة (التكامل وe2e) **تُتخطى افتراضياً**: 39 اختباراً متخطى دون بنية تحتية. لا يوجد CI، والمستودع ليس مستودع git.
4. التخزين تحقق على PostgreSQL عادي فقط، لا على مشروع Supabase فعلي.
5. التتبع (traceability) جزئي: سجلات الـnormalizer لا تحمل `event_id` ولا `trace_id` للأحداث الناجحة، وسجلات dead-letter تفقد الـ`trace_id`.

> **تناقض مع الوثائق:** يصف `docs/IMPLEMENTATION_STATUS.md` و`README.md` المرحلة 1 بأنها «✅ Complete, verified». هذا التدقيق لا يؤيد هذا الادعاء.

---

## 2. Final Objective Verification — التحقق من الهدف النهائي

**السؤال:** هل المسار الكامل Agent → API → Kafka → Normalizer → Supabase يعمل فعلاً؟

**الجواب:** نعم على PostgreSQL 17 (المتوافق مع Supabase)، ولم يُتحقق منه على Supabase الفعلي.

| المقطع | الدليل | النتيجة |
|---|---|---|
| Agent → API | فحص `agent`: الوكيل الحقيقي (`python -m apps.agent run`) يتابع ملف سجل من 600 سطر | 600/600 مخزن، 0 تكرار |
| Generator → API | `python -m tests.e2e.phase1 --batch-events 1000` | 1282 مقبولاً من 1293 مرسلاً (المرفوض هو الأحداث غير الصالحة عمداً) |
| API → Kafka (raw) | الرأس `adis-request-id` والـ`trace_id` في السجل الخام على `adis.system.events` (فحص التتبع) | مطابق |
| Kafka → Normalizer | `KafkaBatchConsumer` على `RAW_TELEMETRY_TOPICS` (`apps/normalizer/service.py:13,69`) | يستهلك الثلاثة |
| Normalizer → `adis.security.events` | المراقِب (observer) رأى 1220 من 1220 حدثاً فريداً | PASS |
| Normalizer → PostgreSQL | استعلامات مباشرة على `adis.security_events` | 1220 صفاً، صف واحد لكل حدث |
| غير الصالح → `adis.deadletter` | 3 سجلات سامة حُقنت في Kafka ووصلت كلها إلى DLQ مع رؤوس `adis-dlq-*` | PASS |
| Supabase الفعلي | لا يوجد مشروع Supabase ولا Supabase CLI | **UNVERIFIED** |

---

## 3. Step-by-Step Status — الحالة خطوة بخطوة

| الخطوة | المتطلب | الحالة | الدليل | المشكلة |
|------|-------------|--------|----------|---------|
| 0.1 | أساس المستودع | **PARTIAL** | البنية مطابقة لـCLAUDE.md، مع إضافتين مبررتين هما `packages/config` و`apps/normalizer`. ruff وmypy نظيفان على 172 ملفاً، ولا اعتماديات دائرية (packages لا تستورد apps) | ليس مستودع git، ولا CI (`.github` غير موجود)، ولا Dockerfiles للخدمات. هياكل فارغة: `packages/redis` و`packages/security` و`apps/detector` و`immune_engine` و`response_engine` و`frontend`. وملف `CLAUDE.txt` مكرر |
| 0.2 | الإعدادات المركزية | **PASS** | Pydantic Settings في `packages/config/sections.py`، والأسرار `SecretStr` بلا قيم افتراضية، و`hide_input_in_errors` (`base.py:77`)، و`ConfigurationError` لا تعرض القيم (`loader.py:27`). المتغيرات الـ17 موجودة في `.env.example` بقيم فارغة للأسرار | أقسام Supabase وRedis وAuth وModelStorage وعَلَما `PROMETHEUS_ENABLED` و`DRY_RUN` لا يقرؤها أي كود تشغيلي. الإنتاج يسمح بـKafka PLAINTEXT وبـ`DB_SSL_MODE=disable` |
| 0.3 | قاعدة البيانات | **PARTIAL** | SQLAlchemy 2 async مع asyncpg، و`pool_pre_ping` (`engine.py:62`)، ومهل للاتصال والأوامر، وجلسة واحدة لكل معاملة مع rollback تلقائي (`database.py`). لا اتصالات عند الاستيراد. الترحيلات تعمل للأمام وللخلف، و`alembic check` لا يجد انحرافاً (اختبار تكامل) | فحص صحة القاعدة موجود في المكتبة (`health.py`) لكن لا تعرضه أي خدمة. لم يُتحقق على Supabase الفعلي (Supavisor وSSL وأدواره) |
| 0.4 | Redis | **FAIL** | `packages/redis/__init__.py` يحتوي docstring فقط (4 أسطر). لا تبعية `redis` في `pyproject.toml`. `RedisSettings` غير مستخدم | لا عميل، ولا فحص صحة، ولا namespaces، ولا TTL، ولا إدارة دورة حياة. **غير منفذ** |
| 0.5 | بنية Kafka | **PARTIAL** | منتج `acks=all` مع idempotence (`clients.py:47`)، وتثبيت الإزاحات بعد المعالجة (`batch_consumer.py:162`)، وDLQ بالبايتات الأصلية. 37 اختبار تكامل نجحت في التشغيل المستقل | اختبار تكامل فشل في التشغيل الكامل. `KafkaConsumer` يثبّت كل سجل على حدة (328 سجل/ث)، ولا تستخدمه أي خدمة. الخدمات تخرج فوراً إذا كان Kafka متوقفاً عند الإقلاع. SASL غير مدعوم (OD-5) |
| 0.6 | الرصد والسجلات | **PARTIAL** | سجلات JSON بكل الحقول المطلوبة، تحقق من سجلات حقيقية. `request_id` يتولّد ويُنشر، و`trace_id` ينتقل HTTP → envelope → رأس Kafka → السجل المُطبَّع → صف القاعدة. لم يُعثر على أي سر في السجلات | سجلات الـnormalizer لا تذكر `event_id` ولا `trace_id` للأحداث الناجحة، وسجلات DLQ فيها `trace_id=null`. لا مقاييس Prometheus (يجمع من نفسه فقط) |
| 1.1 | مخطط الحدث القياسي | **PASS** | `packages/events/canonical/v1.py`: الفئات الخمس وكل الحقول. أكثر من 90 اختبار وحدة (المصفوفة في §8.1)، وتحقق حي لـIPv6 والمنافذ الحدّية والطوابع الزمنية والـmetadata | الطوابع المستقبلية مقبولة بلا حد (قُبل +365 يوماً)، والمنفذ 0 مقبول |
| 1.2 | مخطط Supabase للأحداث | **PARTIAL** | أنواع UUID وTIMESTAMPTZ وINET وJSONB. `UNIQUE (event_id)` (`migration:79`)، والفهارس المطلوبة، وBRIN على `received_at`، وRLS مفعّل | جدول `agents` لا يُكتب أبداً أثناء التشغيل، فكل الصفوف لها `agent_id = NULL`: تحقق التدقيق من 0 صف مرتبط (OD-18). لا ترقيم بالمؤشر (cursor) |
| 1.3 | واجهة FastAPI للاستيعاب | **PASS** | مصنع التطبيق، وlifespan، وحقن الاعتماديات، وحدود الجسم والدفعة. تحقق حي من 400 و401 و413 و415 و422. عند انقطاع Kafka ترجع 503 لا 202، و`/ready` يرجع 503 | الـAPI لا يُقلع إذا كان Kafka متوقفاً (رمز الخروج 3، بلا إعادة محاولة). محدد المعدل داخل العملية فقط (OD-17) |
| 1.4 | وكيل ADIS | **PARTIAL** | UUID ثابت، وspool على القرص (SQLite مع WAL و`synchronous=FULL`)، وسعة محدودة مع ضغط عكسي صريح، وتراجع أسي. تحقق حي: 600/600 رغم انقطاع الـAPI وقتل الوكيل | التسجيل لا يصل إلى جدول `agents`. ملف spool تالف يوقف الوكيل بخطأ غير مُعالَج (رمز الخروج 1). صلاحيات Windows غير مضبوطة (OD-19) |
| 1.5 | خط التطبيع | **PASS** | إدراج ونشر داخل معاملة واحدة، ثم تثبيت الإزاحات. تحقق حي من: الانهيار القسري (1000/1000، صف واحد لكل حدث)، وانقطاع القاعدة، وانقطاع Kafka، والإيقاف السليم (0 إعادة معالجة) | لا فحص صحة ولا مقاييس (OD-22). يخرج إذا كان Kafka متوقفاً عند الإقلاع. التكرارات ذات المحتوى المختلف تُسقَط بصمت (OD-20) |
| 1.6 | التحقق من طرف إلى طرف | **PARTIAL** | تشغيل `tests.e2e.phase1` نجح مرتين، و`TEST_E2E=1 pytest tests/e2e` نجح | تحقق على PostgreSQL لا Supabase. الوكيل ليس ضمن الـharness المُلتزَم (غطته فحوصات التدقيق فقط). الحزمة الكاملة فيها فشل واحد |

---

## 4. Architecture Findings — نتائج المعمارية

1. **الفصل بين الطبقات سليم.**
   - `apps/*` تستورد `packages/*` فقط، ولا تطبيق يستورد تطبيقاً آخر.
   - `packages/*` لا تستورد `apps/*`. تحقق التدقيق بـgrep، ولم يجد أي حالة.
2. **مسار التشغيل الفعلي:** `apps/api` و`apps/normalizer` و`apps/agent`. أما `apps/detector` و`apps/immune_engine` و`apps/response_engine` فهي docstrings فقط، وهذا متوقع لمراحل لاحقة.
3. **مكوّنات منفذة لكنها غير موصولة بالتشغيل:**
   - `packages/kafka/consumer.py` (`KafkaConsumer` لكل سجل): تستخدمه الاختبارات فقط.
   - `packages/database/health.py` (`check_database_health`): لا تستدعيه أي خدمة.
   - `SupabaseSettings` و`AuthSettings` و`ModelStorageSettings` و`RedisSettings`: لا تقرؤها أي خدمة.
   - `PROMETHEUS_ENABLED` و`DRY_RUN`: عَلَمان لا يؤثران على أي سلوك.
   - `packages/security` و`packages/redis`: docstrings فقط.
4. **لا Dockerfiles للخدمات.** الخدمات تعمل كعمليات على المضيف فقط، ولا مدير عمليات يعيد تشغيلها. هذا مهم لأن الـAPI والـnormalizer يخرجان عند غياب Kafka لحظة الإقلاع (انظر §6).
5. **الحزمة (packaging):**
   - hatchling مع جذور استيراد صحيحة.
   - الاعتماديات المُعلنة مستخدمة كلها: aiokafka وalembic وasyncpg وfastapi وhttpx2 وpydantic وpydantic-settings وsqlalchemy وuvicorn.
   - لا اعتمادية `redis`، وهذا منطقي لأن Redis غير منفذ.
6. **التكرار والتنظيم:** منطق التحقق من الاشتراك (topics وgroup_id) موحّد في `validate_subscription`. لم يُعثر على كود ميت داخل مسار التشغيل.
7. **معمارية Supabase:** «خادم موثوق». الجداول في مخطط `adis`، ولا يعرضه Supabase Data API. RLS مفعّل بلا سياسات، أي منع افتراضي لأي دور غير المالك. الخدمات تتصل بدور `postgres` (OD-11: دور بأقل صلاحيات لم يُنشأ بعد).

---

## 5. Database Findings — نتائج قاعدة البيانات

| البند | النتيجة | الدليل |
|---|---|---|
| Async engine وasyncpg | PASS | `packages/database/engine.py`: `create_async_engine`، و`postgresql+asyncpg` |
| التجميع (pooling) | PASS | `pool_size` و`max_overflow` و`pool_timeout` و`pool_recycle` و`pool_pre_ping=True` (`engine.py:57-64`). وضع Supavisor transaction مع `NullPool` وإيقاف prepared statements |
| المهل | PASS | `timeout` و`command_timeout` في `connect_args` (`engine.py:45-46`)، و`db_health_check_timeout_seconds` |
| نطاق المعاملات | PASS | `Database.transaction()` هي `session.begin()`: commit عند النجاح وrollback عند الاستثناء. المستودعات لا تُثبّت بنفسها أبداً (`repository.py`) |
| تسرب الجلسات | PASS | كل الجلسات في `async with`، و`expire_on_commit=False` (`session.py`) |
| الاتصال عند الاستيراد | PASS | لا محركات على مستوى الوحدة؛ المحرك كسول (lazy) |
| الإغلاق | PASS | `Database.dispose()`، وتحقق حي: السجل `database_engine_disposed` ظهر عند الإيقاف السليم |
| فحص الصحة | **PARTIAL** | `check_database_health` مع `SELECT 1` ومهلة ولا يرمي استثناءً، لكن لا تعرضه أي خدمة |
| الترحيلات | PASS | ترحيل واحد `23e849fe26bd`، واختبار downgrade ثم upgrade. `alembic check` أعاد «No new upgrade operations detected» في التشغيل الحقيقي |
| الانحراف بين النماذج والترحيلات | **لا انحراف** | `alembic check` في التكامل، واختبار مساواة DDL في الوحدة |
| حماية `event_id` | PASS على مستوى القاعدة | `sa.UniqueConstraint("event_id")` (`migration:79`)، و`on_conflict_do_nothing(index_elements=[event_id])` (`repositories/security_events.py:101`) |
| الأنواع | PASS | UUID وTIMESTAMPTZ وINET (`src_ip`/`dst_ip`) وJSONB (`payload`)، وCHECK على نطاق المنافذ |
| الفهارس | مناسبة لأنماط الاستعلام | timestamp، و(`event_type`, timestamp)، و(`host_id`, timestamp) و(`agent_id`, timestamp) جزئيان، وsrc/dst IP جزئيان، وBRIN على `received_at`. كلها تطابق `find_events_by_host` و`find_events_by_time_range` والاحتفاظ (retention) |
| طرق المستودع | PASS | `store_event`، و`store_events_batch` (استعلام واحد لربط الوكلاء، فلا N+1)، و`find_event`، و`find_events_by_host`، و`find_events_by_time_range` |
| الاستعلامات غير المحدودة | PASS | `limit ≤ MAX_QUERY_LIMIT=1000` (`repositories/security_events.py:22`) |
| الترقيم (pagination) | **ناقص** | `limit` فقط، بلا cursor أو offset. الصفحات ممكنة بنافذة زمنية فقط (`until` = آخر timestamp) |
| حقن SQL | PASS | معاملات مربوطة. الـf-strings في `spool.py:285` والترحيل تستخدم أسماء ثابتة فقط |
| ربط الوكيل | **FAIL وظيفياً** | `agent_id` يُربط فقط إن كان الوكيل مسجلاً، وجدول `agents` لا يُكتب أبداً. تحقق حي: `SELECT count(*) ... WHERE agent_id IS NOT NULL` أعاد **0**، وعدد صفوف `adis.agents` = **0** |
| ضمانة الترحيل | PASS | `env.py:52` يرفض اتصالاً مخططه الافتراضي `adis`، واختبار تكامل يغطي ذلك |
| Supabase الفعلي | **UNVERIFIED** | الاختبارات على `postgres:17-alpine`. لم يُختبر Supavisor (6543/5432)، ولا `sslmode=require`، ولا سلوك أدوار Supabase أو المخططات المكشوفة |

---

## 6. Kafka Findings — نتائج Kafka

### 6.1 المواضيع (topics)

الكتالوج في `packages/kafka/topics.py`:
- المواضيع الخام: `adis.system.events` و`adis.auth.events` و`adis.network.events` (`RAW_TELEMETRY_TOPICS`)؛
- الموضوع المُطبَّع: `adis.security.events` (`NORMALIZED_EVENTS_TOPIC`)؛
- مواضيع المراحل اللاحقة: `adis.anomalies` و`adis.threats` و`adis.responses`؛
- موضوع الرسائل الميتة: `adis.deadletter`.

الإنشاء التلقائي معطّل على الوسيط، والإنشاء يتم بـ`ensure_topics`. مدة الاحتفاظ 168 ساعة، و720 ساعة لـDLQ.

### 6.2 الـEnvelope

`EventEnvelope` في `packages/events/envelope.py` يحمل الحقول السبعة كلها: `event_id` و`event_version` و`event_type` و`timestamp` (UTC) و`producer` و`trace_id` و`payload`، وهو `extra="forbid"`. الرؤوس (`adis-event-id` و`adis-trace-id` و...) تعكس بيانات الـenvelope الوصفية.

### 6.3 متى تُثبَّت الإزاحات (من الكود)

| المستهلك | نقطة التثبيت | قبل ماذا؟ |
|---|---|---|
| `KafkaBatchConsumer` (يستخدمه الـnormalizer) | `batch_consumer.py:162`: `await self._commit(...)` **بعد** عودة المعالج فقط | المعالج يعود فقط بعد commit قاعدة البيانات، واستلام تأكيدات Kafka للنشر، وكتابة DLQ (`pipeline.py:271-277`). إذا رمى المعالج استثناءً أو `BatchAbortedError` فلا تثبيت |
| `KafkaConsumer` (غير مستخدم تشغيلياً) | `consumer.py:274`: بعد كل سجل، بعد نجاح المعالج أو كتابة DLQ | فشل كتابة DLQ ينتشر ولا يُثبَّت شيء |

**لا يوجد مسار يُثبّت الإزاحة قبل انتهاء المعالجة المطلوبة.** تحقق التدقيق من ذلك عملياً:
- انهيار قسري: بقي 252 مخزناً عند القتل، ثم اكتمل 1000/1000 بعد إعادة التشغيل.
- إيقاف سليم: 0 إعادة معالجة بعد الإعادة.

### 6.4 دلالة التسليم الفعلية (من الكود لا الاستنتاج)

- **Kafka:** نحو المواضيع الخام وموضوع `adis.security.events` التسليم **at-least-once**:
  - المنتج idempotent مع `acks=all`، لكن `retry_async` الخارجي وإعادة الإرسال من العميل قد تكرر السجلات.
  - الـnormalizer ينشر قبل commit القاعدة، فانهيار بينهما يعيد النشر.
- **الصفوف:** **effectively-once** عبر `UNIQUE (event_id)` مع `ON CONFLICT DO NOTHING`، والنشر يقتصر على ما أُدرج فعلاً في المعاملة نفسها.
- **فقدان صامت:** لم يُعثر على مسار له. المخاطر التشغيلية المتبقية:
  - توقف الـnormalizer أكثر من مدة الاحتفاظ (168 ساعة) يعني حذف السجلات الخام قبل معالجتها.
  - الاحتفاظ بإزاحات المجموعة محدود بإعداد الوسيط (افتراضياً 7 أيام). عند انتهائه تُقرأ المواضيع من البداية: تكرار لا فقدان.

### 6.5 حالات الفشل

| الحالة | السلوك الفعلي | الدليل |
|---|---|---|
| JSON تالف | `DeserializationError`، ثم DLQ فوراً مع البايتات الأصلية | e2e: `DeserializationError from adis.network.events` |
| إصدار مخطط غير معروف | عند الـAPI: 422 `unsupported_schema_version`. عند الـnormalizer: `CanonicalEventError`، ثم DLQ | فحص edge، والاختبارات |
| Kafka متوقف أثناء التشغيل | المنتج يعيد المحاولة، ثم 503 بعد 5 ثوانٍ. الـnormalizer يعيد المحاولة بلا حد ولا يثبّت شيئاً | e2e: 16 رداً بـ503، ثم 100/100 خلال 8.8 ثانية من الإعادة |
| Kafka متوقف عند الإقلاع | **الـAPI يخرج** («Application startup failed. Exiting.»، رمز 3). **الـnormalizer يخرج** (رمز 1). مع تحذير `Unclosed AIOKafkaProducer` | فحص startup |
| مهلة النشر | الـAPI: `asyncio.timeout(5)` ثم 503 (`publisher.py:123`). الـnormalizer: `NORMALIZER_PUBLISH_TIMEOUT_SECONDS=30` ثم rollback وإعادة محاولة | الكود، واختبارات الوحدة |
| إعادة محاولة المنتج | `retry_async` بتراجع أسي وjitter لأخطاء aiokafka القابلة لإعادة المحاولة (`producer.py`) | اختبارات الوحدة |
| انهيار المستهلك | لا تثبيت، فالسجلات تُعاد، والتكرار يُكبت بالقيد | اختبار crash |
| إعادة موازنة المجموعة (rebalance) | `CommitFailedError` يُسجَّل ولا يُرمى (`batch_consumer.py:181`) | اختبار وحدة |
| **أداء `KafkaConsumer`** | **328 سجل/ث** (قياس فعلي)، لأنه يثبّت كل سجل على حدة | سبب فشل اختبار التكامل (§12) |
| سباق الإيقاف | `run()` يمسح عَلَم الإيقاف عند بدئه (`consumer.py:236` و`batch_consumer.py:131`). طلب إيقاف قبل `run` يضيع | OD-23؛ الخدمة الحالية تتجنبه |

---

## 7. Agent Findings — نتائج الوكيل

**السؤال الحرج: ماذا يحدث للأحداث إذا كان الـAPI غير متاح لعدة دقائق؟**

**الجواب:** تُخزَّن مؤقتاً على القرص، وتُعاد محاولة إرسالها، ولا تُفقد بصمت. مُثبت عملياً في فحص `agent`:

| الخطوة | النتيجة |
|---|---|
| 300 سطر، والـAPI يعمل | 300 مخزنة |
| إيقاف الـAPI، وإضافة 300 سطر، والانتظار 10 ثوانٍ | لم يُخزَّن شيء جديد (300)؛ الوكيل سجّل `agent_send_retry` |
| **قتل الوكيل قسرياً والـAPI متوقف** | `status`: `queued = 300` مستمرة على القرص |
| إعادة الـAPI (بعد 17.1 ثانية) ثم إعادة الوكيل | **600 صف، 600 `event_id` مميز**، و`queued = 0` |
| إعادة التسجيل | صف تسجيل واحد فقط، لأن معرّفه حتمي (UUIDv5) |

- **الـspool:**
  - SQLite مع WAL و`synchronous=FULL`.
  - السعة تُفرض عند الإلحاق (`spool.py:194`، `SpoolFullError`).
  - الامتلاء يطبّق ضغطاً عكسياً صريحاً: السجل `agent_spool_full`، وإيقاف القراءة، ولا طرد (`agent.py:74`).
  - مؤشرات القراءة (checkpoints) تُحفظ في المعاملة نفسها مع الأحداث.
- **الطابور غير المحدود:** لا يوجد. الحد `AGENT_MAX_QUEUE_EVENTS=100000`، والـquarantine محدود أيضاً مع عدّاد للطرد.
- **الهوية:** ملف `agent_id` يُنشأ حصرياً بصلاحية 0600، والملف التالف لا يُستبدل أبداً (`identity.py:87`، رمز الخروج 2).
- **الإغلاق:** تفريغ نهائي محدود بـ`AGENT_HTTP_TIMEOUT_SECONDS`، مغطى باختبار وحدة (`test_agent.py`).
- **مشكلات:**
  1. **ملف spool تالف يوقف الوكيل تماماً.** `sqlite3.DatabaseError: file is not a database` غير مُعالَج، ورمز الخروج 1 مع traceback. لا يوجد مسار استرداد (نقل الملف جانباً مثلاً)، ولا توثيق.
  2. **التسجيل لا يكتمل خادمياً.** أحداث `system.agent_registered` تُخزَّن كأحداث عادية، لكن جدول `agents` لا يُحدَّث (OD-18)، فلا ربط FK.
  3. صلاحيات مجلد البيانات على Windows غير مضبوطة (OD-19)، والـspool غير مشفّر.
  4. الوكيل ليس جزءاً من الـharness المُلتزَم (`tests/e2e/phase1` يستخدم مولّداً بديلاً).

---

## 8. Normalizer Findings — نتائج خط التطبيع

| # | المتطلب | الحالة | الدليل |
|---|---|---|---|
| 1 | الاشتراك في المواضيع الخام الثلاثة | PASS | `service.py:69`: `topics=RAW_TELEMETRY_TOPICS` |
| 2 | إلغاء التسلسل الآمن | PASS | `deserialize_envelope` مع Pydantic؛ لا pickle ولا eval (grep) |
| 3 | التحقق بالمخطط القياسي | PASS | `from_envelope` بعد التطبيع؛ رفض عدم التطابق بين الـenvelope والـpayload |
| 4 | UTC | PASS | `+05:30` خُزّن كـ`12:00:00Z` (فحص edge)؛ epoch s/ms/µs/ns ضمن 2000–2100 |
| 5 | تطبيع IP | PASS | `2001:DB8:0:0:0:0:0:20` خُزّن كـ`2001:db8::20` في الـpayload وعمود INET؛ الأقواس وIPv4-mapped |
| 6 | تطبيع البروتوكول | PASS | السياسة: أحرف صغيرة، وأرقام IANA، وأسماء مستعارة (`PROTOCOL_ALIASES`، `normalization.py:62`). `TCP` خُزّن `tcp`. الأسماء المجهولة تُرفض ولا تُخمَّن |
| 7 | idempotency لـ`event_id` | PASS | قيد قاعدة بيانات، لا فحص تطبيقي فقط |
| 8 | غير الصالح إلى DLQ | PASS | 3 من 3 سجلات سامة، والرسائل بلا قيم |
| 9 | الصالح إلى `adis.security.events` | PASS | 1220 من 1220 |
| 10 | الحفظ في PostgreSQL | PASS | صف واحد لكل حدث |
| 11 | لا فقدان عند الاستثناءات | PASS | انقطاع الخدمة: إعادة بلا حد. الأخطاء الأخرى: عزل ثم إعادة محدودة ثم DLQ. خطأ برمجي أثناء التطبيع: DLQ لا انهيار متكرر |
| 12 | تثبيت الإزاحات بأمان | PASS | §6.3 |

### 8.1 مصفوفة تغطية التحقق للمخطط القياسي (1.1)

| الحالة | اختبار وحدة | تحقق حي (التدقيق) |
|---|---|---|
| IPv4 صالح وغير صالح (أصفار بادئة، شبكات، أعداد صحيحة) | `test_ip_addresses_are_parsed_and_normalized` و`test_malformed_addresses_are_rejected` | `300.1.1.1` ← 422 |
| IPv6 وIPv4-mapped و zone id | نفس الاختبارات، و`test_flow_endpoints_must_share_an_ip_version` | IPv6 مخزن ومطبَّع |
| نطاق المنافذ 0–65535 والنوع strict | `test_valid_ports` و`test_invalid_ports_are_rejected` | 0 و65535 مقبولان؛ 65536 و-1 و`"abc"` ← 422 |
| المنافذ مع بروتوكول بلا منافذ | `test_ports_are_rejected_for_portless_protocols` | لم يُفحص حياً |
| تحليل الطابع وUTC | `test_timestamps_are_normalized_to_utc` | `+05:30` ← UTC |
| الطوابع الملتبسة (بلا منطقة، epoch، نصوص رقمية) | `test_ambiguous_or_malformed_timestamps_are_rejected` | `"1790000000"` ← 422 |
| الطوابع المستقبلية والقديمة | **لا اختبار ولا قاعدة** | +365 يوماً و1990 مقبولة |
| metadata مجهولة ومتداخلة | `test_unknown_vendor_data_survives_a_json_round_trip` | محفوظة كما هي |
| حجب مفاتيح الاعتماد | `test_credential_keys_are_redacted_at_any_depth` | `password` و`Authorization` ← `[REDACTED]` |
| رفض الحقول المجهولة في المستوى الأعلى | `test_unknown_top_level_fields_are_rejected` | `foo` ← 422 |
| حقول ناقصة | `test_timestamp_is_required` و`test_success_is_required` و`test_flows_require_endpoints_and_protocol` | `dst_ip` و`timestamp` ← 422 |
| أنواع خاطئة (`success`) | `test_success_must_be_a_boolean` | `"yes"` ← 422 |
| القيم المُلاحَظة (NUL، الطول) | `test_usernames_are_preserved_but_made_storable` | NUL ← U+FFFD، مخزن |
| الإصدار (schema versioning) | `test_unknown_schema_versions_are_rejected_with_the_supported_list` و`test_committed_schema_matches_the_models` | `9.0` ← 422 |
| JSON round-trip | `test_json_round_trip_is_lossless` و`test_envelope_survives_the_kafka_wire_format` | مطابق |
| التوافق العكسي | استراتيجية موثقة (وحدة لكل إصدار رئيسي، ولقطة JSON Schema). **إصدار واحد فقط؛ لم تُختبر الترقية** | – |

### 8.2 اختبار الـidempotency الحرج (مرة، مرتين، عشر مرات)

- **الآلية:** `INSERT … ON CONFLICT (event_id) DO NOTHING RETURNING event_id` داخل معاملة، والنشر يقتصر على المُدرج. عدد مرات المعالجة لا يغيّر النتيجة: **صف منطقي واحد**، وهذا مضمون على مستوى القاعدة بالقيد لا بفحص تطبيقي.
- **ما اختُبر فعلاً:**

  | الحالة | النتيجة |
  |---|---|
  | مرة واحدة | الحالة الأساسية |
  | مرتان | 50 حدثاً أعيد إرسالها، وتكرار داخل الدفعة: صف واحد ونشر واحد |
  | إعادة كل التاريخ بمجموعة مستهلكين جديدة | اختبار التكامل `test_replaying_everything_creates_no_duplicates`: صف واحد ونشر واحد |
  | إعادة التسليم بعد انهيار | 1000/1000، و`max_rows_per_event = 1` |

  **عشر مرات حرفياً لم تُختبر.** لكنها محكومة بنفس القيد، و`GROUP BY event_id HAVING count(*) > 1` = 0 على الجدول كله.

### 8.3 اختبار الانهيار الحرج

**التسلسل:** استلام الحدث ← كتابة إلى القاعدة ← انهيار قبل تثبيت الإزاحة ← إعادة تسليم.

- **إذا انهار بعد commit القاعدة:** إعادة التسليم تصطدم بالقيد، فلا صف جديد ولا نشر جديد، ثم تُثبَّت الإزاحة. **آمن.**
- **إذا انهار بين النشر وcommit القاعدة:** الاتصال ينقطع فتتراجع المعاملة، وعند الإعادة يُدرج الحدث ويُنشر مرة ثانية. النتيجة صف واحد (نشر at-least-once).
- **عملياً:**
  - قُتل الـnormalizer بـTerminateProcess عند 252 من 1000.
  - بعد الإعادة: 1000 مميزاً، و0 مفقود، و0 نشر إضافي، والتعافي في 15.5 ثانية (معظمها مهلة جلسة المجموعة).

### 8.4 اختبار فشل القاعدة الحرج

**السلوك الفعلي عند تعذّر الوصول إلى القاعدة:**
- يعيد المحاولة بتراجع (`normalizer_retry`)؛
- **لا** يرسل إلى DLQ؛
- **لا** يثبّت الإزاحة؛
- **لا** ينهار؛
- **لا** يفقد الحدث.

**الأدلة العملية:**

| الحالة | النتيجة |
|---|---|
| الـnormalizer يعمل ثم تتوقف القاعدة | e2e: 100/100 خُزّنت خلال 4.1 ثانية من إعادة التشغيل |
| القاعدة متوقفة عند إقلاع الـnormalizer | فحص startup: 20/20 بعد التعافي، و3 إعادات مسجلة، والعملية بقيت حية |

---

## 9. API Findings — نتائج الواجهة

| البند | النتيجة | الدليل |
|---|---|---|
| `GET /health` و`GET /ready` | PASS | `/ready` يسأل وسيطاً فعلياً (`publisher.py:104`، `ping()`). تحقق حي: 503 أثناء انقطاع Kafka |
| `POST /api/v1/events` و`/batch` | PASS | 202 مع `event_id` و`trace_id`؛ دفعة جزئية بفهارس |
| مصنع التطبيق وlifespan وDI | PASS | `app.py:74-79`؛ `Depends` للعميل والخدمات |
| التحقق القياسي | PASS | `parse_canonical_event` |
| حد الجسم | PASS | فحص `Content-Length` ثم فحص أثناء القراءة المتدفقة (`dependencies.py`). تحقق حي: 1.2MB ← 413 |
| حجم الدفعة | PASS | `api_max_batch_size` (`events.py:133`). تحقق حي: 501 ← 413، والدفعة الفارغة ← 422 |
| JSON تالف | PASS | 400 `invalid_json`؛ مصفوفة بدل كائن ← 422 |
| نوع المحتوى والمصادقة | PASS | 415 للنوع الخاطئ؛ 401 بلا رمز أو برمز خاطئ؛ المصادقة قبل قراءة الجسم |
| `request_id` و`trace_id` | PASS | رأس `X-Request-ID`؛ `traceparent` محترم؛ الاستجابة تعيد `trace_id` |
| OpenAPI | PASS | مولّد مع مكونات المخطط القياسي، ومغطى باختبار |
| لا عمل ML في الطلب | PASS | المعالجة تقتصر على تحقق ثم نشر إلى Kafka |
| الضغط العكسي | PARTIAL | الطلب محدود بـ`API_PUBLISH_TIMEOUT_SECONDS=5`، وحد المعدل لكل عميل. **لا حد للطلبات المتزامنة** (`limit_concurrency` غير مضبوط في uvicorn)، وكل دفعة قد تنشئ حتى 500 مهمة نشر |
| حد المعدل | PARTIAL | token bucket داخل العملية؛ لا يعمل عبر عدة نسخ (OD-17) |
| الإقلاع وKafka متوقف | **يخرج** | رمز 3، بلا إعادة محاولة |

**اختبار فشل Kafka الحرج:** هل يمكن أن يخبر الـAPI العميل بقبول حدث لم يُقبل؟ **لا.**
- الـ202 تُرجع فقط بعد انتهاء `send_and_wait` لكل سجل (`acks=all`) داخل `asyncio.timeout`.
- المهلة أو أخطاء النشر تتحول إلى `PublishUnavailableError`، ثم 503 مع `Retry-After` (`publisher.py:123,128`).
- تحقق حي: 16 رداً بـ503 أثناء الانقطاع، ثم 100/100 بعد التعافي.
- قد يصل جزء من دفعة إلى Kafka قبل المهلة ثم يُعاد إرسالها. النتيجة تكرار في الموضوع الخام يكبته الـnormalizer.

---

## 10. Observability Findings — نتائج الرصد

- **البنية:** كل سطر JSON يحمل `timestamp` و`level` و`service` و`environment` و`message` و`request_id` و`trace_id` و`event_id` و`host_id` و`threat_id` و`action` و`latency_ms`. تحقق من سجلات حقيقية: 0 سطر غير JSON في `api.log` و`normalizer.log`.
- **السجلات الحساسة:** بحث في السجلات الحقيقية بعد إرسال `password` و`Authorization: Bearer …` داخل الـmetadata، مع رمز الـAPI وكلمة مرور القاعدة: **0 ظهور لأي منها**. الحجب مطبّق في `redaction.py:99` وفي مُحقِّق الـmetadata.
- **سجلات الإقلاع والإيقاف:** `kafka_producer_started` و`kafka_consumer_started` و`kafka_consumer_stopped` و`normalizer_stopped` و`database_engine_disposed` كلها ظهرت في فحص shutdown. لا يوجد سطر «api started/stopped» صريح؛ يغني عنه `kafka_producer_started` و`stopped`.

### اختبار التتبع (حدث واحد)

- `event_id = 390c55f0-00d0-4550-afb6-8fbce59a9124`
- `trace_id = 7840e9bef36e3bf64ff1e3eac2410c73`
- `request_id = 62592265378c4a75b9076943ca029d28`

| المحطة | هل يمكن الوصول بـevent_id أو trace_id؟ |
|---|---|
| سجلات الـAPI | نعم بالـ`trace_id` والـ`request_id` (`http_request` و`api_events_ingested`)، **لكن `event_id = null`** |
| envelope Kafka الخام | نعم: `event_id` و`trace_id` في الـenvelope، ورؤوس `adis-trace-id` و`adis-request-id` |
| سجلات الـnormalizer | **لا**: لا `event_id` ولا `trace_id` لأي حدث ناجح (سجل مستوى الدفعة فقط) |
| سجل Kafka المُطبَّع | نعم (نُشر مرة واحدة، بنفس `trace_id`) |
| صف القاعدة | نعم: `payload.trace_id` مطابق، و`metadata.adis_ingestion.request_id` مطابق، ومعه `source_topic` و`partition` و`offset` |

**النتيجة: PARTIAL.** يمكن تتبع دورة الحياة كاملة بالجمع بين رؤوس Kafka وصف القاعدة وسجل الـAPI. لكن سجلات الـnormalizer لا تساعد على تتبع حدث بعينه. وسجلات DLQ تحمل `trace_id=null` حتى حين يكون الـtrace معروفاً، لأن السجل يُكتب خارج `log_context` الخاص بالسجل.

- **المقاييس:** لا يوجد أي `/metrics`. `infrastructure/prometheus/prometheus.yml` يجمع من Prometheus نفسه فقط، و`PROMETHEUS_ENABLED` لا أثر له.
- **ضجيج:** كل رد 503 يسجّل stack trace كاملاً على مستوى ERROR (16 مرة في انقطاع واحد).

---

## 11. Security Findings — نتائج الأمان

| البند | النتيجة |
|---|---|
| أسرار مضمّنة في الكود | **لا شيء**. الـgrep وجد قيماً اصطناعية للاختبارات فقط (مثل `"agent-token-" + "x"*32`). لا ملف `.env`، ولا ملفات workflow |
| `.env.example` | كل المتغيرات السرية فارغة |
| مفتاح Supabase Service Role | يظهر في `packages/config` (`SecretStr`) وقائمة الحجب فقط. **`frontend/` فارغ**، فلا تعرض له في الواجهة |
| تسريب السجلات | لا شيء (§10) |
| حقن SQL | لا (معاملات مربوطة) |
| إلغاء التسلسل غير الآمن | لا pickle ولا yaml.load ولا eval |
| الطلبات الضخمة | محدودة: الجسم 1MiB، والحدث 128KiB، والدفعة 500، والـmetadata 64KiB وعمق 10 |
| المصادقة | رموز bearer لكل عميل، تُحفظ خلاصات SHA-256 فقط في الذاكرة |
| التفويض | قدرة واحدة (الاستيعاب). لا أدوار ولا ربط للرمز بـ`agent_id`، فأي عميل يمكنه ادعاء `agent_id` أو `host_id` لغيره (OD-16) |
| CORS | غير مُعد، والمتصفحات ترفض الطلبات من أصول أخرى (مناسب لاستيعاب خادم إلى خادم) |
| أمان الاتصال | الإنتاج يفرض تحديد `DB_SSL_MODE` صراحة لكنه يسمح بـ`disable`. Kafka `PLAINTEXT` مسموح في الإنتاج. SASL غير مدعوم (OD-5 وOD-10 وOD-12) |
| Docker | المنافذ مربوطة بـ127.0.0.1، والأسرار عبر متغيرات مطلوبة بلا افتراضيات. كلمة مرور Redis تمر في سطر أوامر `redis-server` (مرئية في قائمة عمليات الحاوية) |
| RLS | مفعّل على `adis.agents` و`adis.security_events` بلا سياسات (منع افتراضي). المخطط غير مكشوف لـPostgREST. معمارية «خادم موثوق» موثقة |
| سلامة التكرار | التكرار ذو المحتوى المختلف يُسقط بصمت. معرّفات أحداث السجلات في الوكيل حتمية (UUIDv5)، فحامل رمز استيعاب يمكنه نظرياً «حجز» معرّف حدث مستقبلي (OD-20) |
| الطوابع المستقبلية | مقبولة بلا حد، وقد تُستغل لإخفاء أحداث عن استعلامات النوافذ الزمنية |

---

## 12. Test Results — نتائج الاختبارات

| الأمر | النتيجة |
|---|---|
| `python -m ruff check .` | All checks passed |
| `python -m ruff format --check .` | 189 files already formatted |
| `python -m mypy` | Success: no issues found in 172 source files |
| `python -m pytest tests/unit -q -rs` | **1327 passed، 0 failed، 1 skipped** (`test_identity_file_is_private`: POSIX فقط) |
| `python -m pytest -q` (بدون بنية تحتية، وهو السلوك الافتراضي و`make test`) | **1327 passed، 0 failed، 39 skipped**: 37 تكامل وe2e واحد وPOSIX واحد |
| `TEST_DATABASE_URL=… TEST_KAFKA_BOOTSTRAP_SERVERS=localhost:9092 python -m pytest tests/integration -q -rs` (التشغيل الأول) | **37 passed، 0 failed، 0 skipped** (210 ثانية) |
| `TEST_E2E=1 TEST_DATABASE_URL=… TEST_KAFKA_BOOTSTRAP_SERVERS=… python -m pytest -q -rs` (الحزمة الكاملة) | **1364 passed، 1 failed، 1 skipped** (334 ثانية) |
| إعادة `pytest tests/integration tests/e2e -q -rf` | **37 passed، 1 failed**: `tests/integration/kafka/test_kafka.py::test_published_event_is_consumed_and_committed` (TimeoutError) |
| `python -m tests.e2e.phase1 --batch-events 1000` | **PASS** (كل الفحوص) |

### تحليل الفشل

- الاختبار يقرأ `adis.security.events` من البداية بمجموعة جديدة، وينتظر سجلاً واحداً 30 ثانية.
- الموضوع صار يحتوي **39,653 سجلاً**، و`KafkaConsumer` يعالج **328 سجل/ث** لأنه يثبّت كل سجل على حدة (`consumer.py:274`). لذلك يتسع وقت الاختبار لنحو 10,000 سجل فقط.
- الموضوع تضخم لأن اختبارات تكامل الـnormalizer تنفّذ `TRUNCATE` لجداول القاعدة، ثم تعيد قراءة التاريخ الخام بمجموعات جديدة، فتعيد نشر آلاف الأحداث في كل تشغيل.

**التصنيف:** اختبار معتمد على كمية البيانات (غير حتمي)، مع قيد أداء حقيقي في `KafkaConsumer`. **حزمة الاختبارات ليست خضراء حالياً في بيئة مستمرة.**

### الاختبارات المتخطاة

- في التشغيل الافتراضي (`make test` أو `pytest`) **كل اختبارات التكامل الـ37 وe2e تتخطى صمتاً**. لا CI يشغّلها.
- لم تُشغَّل على خدمات حقيقية إلا يدوياً: مرة في تشغيل التحقق السابق من اليوم نفسه، ومرة في هذا التدقيق. **في الإعداد الافتراضي تُعد UNVERIFIED.**
- التخطي الوحيد المتبقي مع البنية التحتية هو اختبار صلاحيات POSIX على Windows، وهو **UNVERIFIED** على هذه المنصة.

---

## 13. End-to-End Test — اختبار من طرف إلى طرف

**التشغيل الأساسي:** `python -m tests.e2e.phase1 --batch-events 1000` (run `p1-20260925T204139-88928e`، النتيجة PASS).

| السيناريو | المرسل | المقبول | المُطبَّع | المخزن | التكرارات | الفاشل | DLQ | p50 | p95 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| أحداث مفردة (نظام، مصادقة، شبكة) | 3 | 3 | 3 | 3 | 0 | 0 | 0 | 31 ms | 31 ms |
| دفعات (10 × 100 مختلطة) | 1000 | 1000 | 1000 | 1000 | 0 | 0 | 0 | 532 ms | 765 ms |
| غير صالح وسجلات سامة | 18 | 7 | 7 | 7 | 0 | 8 | 3 | 32 ms | 94 ms |
| تكرارات (إعادة إرسال، وتكرار داخل دفعة) | 72 | 72 | 10 | 10 | 62 | 0 | 0 | 47 ms | 47 ms |
| انقطاع القاعدة (15.6 ث) | 100 | 100 | 100 | 100 | 0 | 0 | 0 | 19.6 s | 19.7 s |
| انقطاع Kafka (20.4 ث) | 100 | 100 | 100 | 100 | 0 | 0 | 0 | 29.2 s | 29.2 s |
| **المجموع** | **1293** | **1282** | **1220** | **1220** | **62** | **8** | **3** | 641 ms | 29.2 s |

**فحوصات تكميلية** (`audit_runtime.py edge`):
- 8 أحداث صالحة حدّية، كلها 202 ومخزنة: IPv6، والمنفذان 0 و65535، وطابع +365 يوماً، و1990، و`+05:30`، وmetadata متداخلة مع اعتمادات، وNUL في `username`، و`TCP`.
- 10 أحداث غير صالحة، كلها 422 وتُسمّي الحقل: حقل مجهول، ومنفذ `"abc"`، و`success="yes"`، و`dst_ip` ناقص، و`timestamp` ناقص، و`300.1.1.1`، و65536، و-1، ونص رقمي كطابع، وإصدار `9.0`.
- أخطاء البروتوكول: دفعة فارغة 422، وJSON تالف 400، ونوع المحتوى 415، وبلا رمز أو برمز خاطئ 401، ودفعة 501 تعطي 413، وجسم 1.2MB يعطي 413.
- تكرار داخل دفعة: قُبل مرتين، وخُزّن ونُشر مرة واحدة.

**الوكيل الحقيقي** (`audit_runtime.py agent`): 600 سطر، و600 صف، و600 مميز، و0 مفقود، مع قتل الوكيل أثناء انقطاع الـAPI.

---

## 14. Failure Recovery Results — نتائج التعافي من الأعطال

| العطل | النتيجة | فقدان؟ | تكرار صفوف؟ | ملاحظة |
|---|---|---|---|---|
| انقطاع Kafka (20.4 ث) | الـAPI يرجع 503 والعملاء يعيدون المحاولة؛ الـnormalizer يعيد المحاولة | لا | لا | 100/100 خلال 8.8 ث من الإعادة |
| انقطاع القاعدة (15.6 ث) | الـAPI يقبل (Kafka متاح)؛ الـnormalizer يعيد المحاولة ولا يرسل إلى DLQ | لا | لا | 100/100 خلال 4.1 ث |
| انقطاع Redis | **لا ينطبق**: لا يستخدم أي كود Redis، وكل الاختبارات جرت دون حاوية Redis | – | – | خطوة 0.4 غير منفذة |
| انهيار الـnormalizer (قتل قسري) | إعادة تسليم الدفعة غير المثبّتة | لا (1000/1000) | لا | تعافٍ في 15.5 ث |
| إعادة تشغيل الـnormalizer بسلام | الإزاحات مثبّتة | – | – | 0 إعادة معالجة |
| إعادة تشغيل الـAPI أثناء عمل الوكيل | الوكيل يخزّن مؤقتاً ويعيد المحاولة | لا | لا | 17.1 ث انقطاع |
| انهيار الوكيل مع spool ممتلئ جزئياً | الطابور محفوظ على القرص | لا (300 محفوظة) | لا | – |
| إعادة كل التاريخ بمجموعة جديدة | كبت كامل | – | لا | اختبار التكامل |
| **إقلاع الـAPI وKafka متوقف** | **خروج فوري (رمز 3)** | – | – | يحتاج مشرف عمليات غير موجود |
| **إقلاع الـnormalizer وKafka متوقف** | **خروج (رمز 1)** | – | – | نفس الملاحظة |
| إقلاع الـnormalizer والقاعدة متوقفة | يبقى حياً ويعيد المحاولة | لا (20/20) | لا | – |
| spool تالف للوكيل | **خروج (رمز 1) بخطأ غير مُعالَج** | – | – | لا استرداد |

---

## 15. Data Integrity — سلامة البيانات

مقارنة الحدث المرسل بالـpayload المخزن لكل الأحداث الحدّية (`audit_runtime.py edge`، قسم `integrity`):

- **الحقول القياسية محفوظة كلها بلا فروق،** مع الاستثناءات المتوقعة التالية:
  - `received_at` يختمه الخادم عمداً (حماية للاحتفاظ).
  - عناوين IP بصيغتها القياسية (`2001:DB8:0:0:0:0:0:20` خُزّن `2001:db8::20`)، والقيمة المنطقية مطابقة.
  - البروتوكول بأحرف صغيرة.
  - الطوابع محولة إلى UTC وتمثل اللحظة نفسها.
  - `NUL` في `username` يصبح `U+FFFD` (موثق: القيم المُلاحَظة تُجعل قابلة للتخزين ولا تُرفض).
- **الـmetadata:**
  - محفوظة كاملة، بما فيها البنى المتداخلة.
  - مفاتيح الاعتماد (`password` و`Authorization`) تُستبدل بـ`[REDACTED]`، وهذا فقدان مقصود.
  - يُضاف `metadata.adis_ingestion`، ويستبدل أي قيمة مزيفة يرسلها المنتج.
- **نوع الحدث والفئة** محفوظان.
- **الأعمدة المُسقَطة:** `src_ip` و`dst_ip` و`src_port` و`dst_port` و`protocol` و`timestamp` و`received_at` تطابق الـpayload. `payload` هو المرجع الكامل.
- **فقدان غير مقصود:** لم يُعثر على أي فقدان. ملاحظة: عمود `agent_id` (FK) دائماً NULL لأن جدول `agents` فارغ، لكن القيمة الأصلية محفوظة في `payload.agent_id`.

---

## 16. Performance Sanity Results — فحص الأداء الأساسي

ليس قياساً معيارياً (benchmark). بيئته: جهاز تطوير واحد عليه Docker Desktop، ونسخة normalizer واحدة، وPostgreSQL وKafka محليان.

| القياس | القيمة |
|---|---|
| 1000 حدث في 10 دفعات متتالية | المرسل 1000، والمقبول 1000، والمُطبَّع 1000، والمخزن 1000، والفاشل 0، والتكرارات 0، وDLQ 0 |
| زمن الوصول من طرف إلى طرف (الإرسال حتى الظهور على `adis.security.events`) | **p50 532 ms، p95 765 ms** |
| زمن القبول (HTTP 202 لدفعة 100) | p50 31 ms، p95 46 ms |
| الحالة المستقرة (1093 حدثاً) | p50 469 ms، p95 765 ms |
| المعدل التقريبي | نحو 900 حدث/ث من طرف إلى طرف. السيناريو استغرق نحو 1.1 ث لـ1000 حدث (من طوابع سجل الـharness) |
| `KafkaConsumer` (لكل سجل) | 328 سجل/ث (قياس مستقل، 10 ث) |

---

## 17. Missing Requirements — المتطلبات الناقصة

1. **Redis (0.4):** عميل async، ودورة حياة، وفحص صحة، وnamespaces، وTTL، ومعالجة الأعطال. كلها غير موجودة.
2. **فحوص الصحة الموصولة:** فحص صحة القاعدة لا تعرضه أي خدمة، وفحص Redis غير موجود، والـnormalizer بلا health أو readiness.
3. **التحقق على Supabase الفعلي:** SSL وSupavisor والأدوار والمخططات المكشوفة وRLS مع أدوار Supabase.
4. **سجل الوكلاء:** لا مستهلك يحدّث جدول `agents` من أحداث التسجيل (OD-18).
5. **CI وإدارة الإصدارات:** ليس مستودع git، ولا pipeline يشغّل اختبارات التكامل وe2e.
6. **الإشراف على العمليات:** لا Dockerfiles ولا إعادة تشغيل تلقائية، مع أن الخدمات تخرج عند غياب Kafka لحظة الإقلاع.
7. **المقاييس:** لا Prometheus instrumentation (أُجّل رسمياً إلى المرحلة 6 في IMPLEMENTATION_STATUS دون موافقة صريحة موثقة).
8. **تتبع لكل حدث في سجلات الـnormalizer،** و`trace_id` في سجلات DLQ.

---

## 18. Technical Debt — الدين التقني

(منفصل عن الأعطال الوظيفية)

- **`KafkaConsumer`** (غير مستخدم تشغيلياً):
  - تثبيت لكل سجل، أي بطء.
  - يرسل الأعطال العابرة إلى DLQ بعد عدد محدود من المحاولات. لو استُخدم لمستهلك يكتب إلى القاعدة لأرسل أحداثاً صالحة إلى DLQ أثناء الانقطاع.
  - لا يعالج `CommitFailedError`.
- **سباق الإيقاف قبل التشغيل** في المستهلكَين (OD-23).
- **نظافة بيئة الاختبار:** اختبارات تكامل الـnormalizer تفرغ القاعدة (`TRUNCATE`) ثم تعيد قراءة التاريخ، فيتضخم `adis.security.events` في الوسيط المشترك.
- **هياكل فارغة:** `packages/security` و`packages/redis` و`apps/{detector,immune_engine,response_engine}` و`ml/*` و`frontend` و`infrastructure/{docker,kafka}`.
- **إعدادات غير موصولة:** Supabase وAuth وModelStorage وRedis و`PROMETHEUS_ENABLED` و`DRY_RUN`.
- **توثيق قديم:** مثال docstring في `packages/config/__init__.py:8` (`class AgentSettings(AppSettings, KafkaSettings)`) لا يطابق القسم الحقيقي. `CLAUDE.txt` نسخة مكررة.
- **تجربة المطور المحلي:**
  - compose يتطلب كل الأسرار حتى لتشغيل خدمة واحدة؛ `make` غير متوفر على Windows.
  - README Quick Start (`make infra-up`) لا يشغّل قاعدة بيانات ولا ترحيلات ولا الخدمات؛ لا يوجد دليل واحد «شغّل المسار محلياً».
  - جدول «Local infrastructure» في DEVELOPMENT.md لا يذكر `postgres-test`.
- **الترقيم:** المستودع لا يوفر cursor pagination.
- **الضجيج:** stack trace كامل على مستوى ERROR لكل 503.

---

## 19. Findings by Severity — النتائج حسب الخطورة

**العدد:** CRITICAL: 0 · HIGH: 4 · MEDIUM: 9 · LOW: 9

### CRITICAL

لا يوجد. لم يُعثر على:
- فقدان صامت للأحداث؛
- قبول كاذب؛
- تثبيت إزاحة قبل المعالجة؛
- صفوف مكررة؛
- أسرار مكشوفة.

### HIGH

**ADIS-P01-001**
- **الخطورة:** HIGH
- **المكوّن:** `packages/redis` (الخطوة 0.4)
- **المشكلة:** بنية Redis غير منفذة: لا عميل ولا فحص صحة ولا namespaces ولا TTL ولا دورة حياة.
- **الأثر:** المرحلة 0 غير مكتملة، ومتطلب «Redis health checks» غير متحقق. المكونات المستقبلية (حد المعدل الموزع OD-17، والذاكرة المناعية) تفتقد أساسها.
- **الدليل:** `packages/redis/__init__.py` (docstring من 4 أسطر)؛ لا تبعية `redis` في `pyproject.toml`؛ grep لا يجد أي استخدام.
- **التوصية:** تنفيذ `packages/redis`:
  - عميل `redis.asyncio` مع pool ومهل؛
  - `health_check()`؛
  - بادئات مفاتيح؛
  - تسلسل JSON وTTL إلزامي؛
  - `dispose()`؛
  - اختبارات وحدة وتكامل؛
  - وصل فحص الصحة بالخدمات التي تستخدمه.

**ADIS-P01-002**
- **الخطورة:** HIGH
- **المكوّن:** `tests/integration/kafka/test_kafka.py` و`packages/kafka/consumer.py`
- **المشكلة:** الاختبار `test_published_event_is_consumed_and_committed` يفشل عندما يحتوي `adis.security.events` على أكثر من 10,000 سجل تقريباً. السبب قراءة من البداية بمهلة 30 ث، بينما يعالج `KafkaConsumer` 328 سجل/ث.
- **الأثر:** حزمة الاختبارات حمراء في بيئة الاختبار المستمرة (فشل مرتين في التدقيق)، ونتيجة القبول غير قابلة للتكرار.
- **الدليل:** 1364 passed و1 failed؛ الموضوع 39,653 سجلاً؛ التثبيت لكل سجل في `consumer.py:274`.
- **التوصية:**
  - يبدأ الاختبار من نهاية الموضوع أو من إزاحة النشر (seek)، أو يستخدم موضوعاً معزولاً.
  - تثبيت الإزاحات في `KafkaConsumer` كل N سجلات أو كل فترة زمنية.
  - إيقاف إعادة نشر التاريخ في اختبارات الـnormalizer (§18).

**ADIS-P01-003**
- **الخطورة:** HIGH
- **المكوّن:** المستودع والاختبارات
- **المشكلة:** الاختبارات الحرجة (37 تكامل وe2e) تُتخطى افتراضياً في `make test` و`pytest`. لا يوجد CI، والمستودع ليس مستودع git.
- **الأثر:** يمكن أن ينكسر المسار دون أن يلاحظ أحد، ومعيار القبول «critical tests actually run» غير مضمون.
- **الدليل:** 1327 passed و39 skipped بدون بنية تحتية؛ `.github` غير موجود؛ `git rev-parse` يرجع «not a git repository».
- **التوصية:**
  - `git init` مع `.gitattributes`.
  - pipeline CI يشغّل `make test-infra-up` ثم اختبارات التكامل وe2e.
  - فشل صريح بدل التخطي في CI، مثل `--strict` أو متغير `REQUIRE_INTEGRATION=1`.

**ADIS-P01-004**
- **الخطورة:** HIGH
- **المكوّن:** قاعدة البيانات (0.3 و1.2 و1.6)
- **المشكلة:** كل التحقق جرى على `postgres:17-alpine`، ولم يُتحقق على مشروع Supabase فعلي.
- **الأثر:** سلوكيات لم تُختبر: Supavisor transaction pooler (المنفذ 6543 مع `NullPool` وإيقاف prepared statements)، و`sslmode=require`، ودور `postgres` في Supabase، وعدم كشف مخطط `adis`، وRLS مع `anon` و`authenticated`. الهدف ينص على Supabase مصدراً للحقيقة.
- **الدليل:** بيئة التشغيل؛ لا Supabase CLI؛ لا `.env`.
- **التوصية:**
  - تشغيل الترحيلات واختبارات التكامل وe2e على مشروع Supabase للتطوير (أو `supabase start`)، في الوضعين direct/session pooler وtransaction pooler.
  - التحقق من أن `anon` لا يرى `adis.*`.

### MEDIUM

**ADIS-P01-005**
- **الخطورة:** MEDIUM
- **المكوّن:** الـnormalizer والرصد
- **المشكلة:**
  - سجلات النجاح على مستوى الدفعة فقط، بلا `event_id` ولا `trace_id`.
  - سجلات DLQ فيها `trace_id=null` و`event_id=null`، حتى لو كانت معروفة، لأنها تُكتب خارج `log_context`.
  - سجل `api_events_ingested` بلا معرّفات أحداث.
- **الأثر:** تتبع حدث بعينه عبر السجلات غير ممكن؛ يتطلب فحص Kafka والقاعدة.
- **الدليل:** `pipeline.py:179` و`pipeline.py:279-302`؛ فحص التتبع: `normalizer_log_mentions_event_id = false`.
- **التوصية:**
  - سجل debug لكل حدث، أو قائمة المعرّفات في سطر الدفعة.
  - تمرير `trace_id` و`event_id` المعروفين إلى سجل DLQ.

**ADIS-P01-006**
- **الخطورة:** MEDIUM
- **المكوّن:** الوكيل وقاعدة البيانات (1.2 و1.4)
- **المشكلة:** التسجيل لا يكتمل: أحداث `system.agent_registered` لا تحدّث جدول `agents`، فـ`security_events.agent_id` دائماً NULL.
- **الأثر:** لا سجل وكلاء، ولا `first_seen`/`last_seen`، ولا استعلامات حسب الوكيل عبر الـFK.
- **الدليل:** تحقق حي: 0 صف مرتبط، و0 صف في `adis.agents`؛ OD-18.
- **التوصية:** مستهلك سجل وكلاء (upsert) من `adis.security.events`.

**ADIS-P01-007**
- **الخطورة:** MEDIUM
- **المكوّن:** الـAPI والـnormalizer (دورة الحياة)
- **المشكلة:** الخروج فوراً إذا كان Kafka غير متاح عند الإقلاع (الـAPI برمز 3، والـnormalizer برمز 1)، بلا إعادة محاولة. مع تحذير `Unclosed AIOKafkaProducer`. ولا Dockerfiles أو مشرف لإعادة التشغيل.
- **الأثر:** إعادة تشغيل الوسيط قبل الخدمات، أو ترتيب إقلاع خاطئ، تترك المسار متوقفاً حتى تدخل يدوي.
- **الدليل:** فحص startup؛ `app.py:75` و`producer.py:135`.
- **التوصية:**
  - إعادة محاولة الإقلاع بتراجع، أو الاعتماد على مشرف موثق (Dockerfiles مع `restart: unless-stopped`).
  - إغلاق العميل عند فشل `start()`.

**ADIS-P01-008**
- **الخطورة:** MEDIUM
- **المكوّن:** الرصد وفحوص الصحة
- **المشكلة:** لا مقاييس Prometheus، وPrometheus يجمع من نفسه فقط، و`PROMETHEUS_ENABLED` بلا أثر. الـnormalizer بلا health أو readiness، وفحص صحة القاعدة غير معروض.
- **الأثر:** لا رؤية لتأخر المستهلك (consumer lag) ولا للأعطال إلا من السجلات.
- **الدليل:** `infrastructure/prometheus/prometheus.yml`؛ grep لـ`check_database_health`؛ OD-22.
- **التوصية:** مستمع health وmetrics صغير للعمال، ومقاييس للاستيعاب والتأخر والإعادات وDLQ.

**ADIS-P01-009**
- **الخطورة:** MEDIUM
- **المكوّن:** `packages/kafka/consumer.py`
- **المشكلة:** `KafkaConsumer` المشترك:
  - يثبّت كل سجل على حدة (328 سجل/ث)؛
  - يرسل الأعطال العابرة إلى DLQ بعد `KAFKA_RETRY_MAX_ATTEMPTS`؛
  - لا يعالج `CommitFailedError`.
- **الأثر:** أي مستهلك مستقبلي (مثل الـdetector) يعتمد عليه سيكون بطيئاً، وقد يرسل أحداثاً صالحة إلى DLQ أثناء انقطاع قاعدة البيانات.
- **الدليل:** `consumer.py:274`؛ `_is_retriable_handler_error`؛ القياس.
- **التوصية:** مواءمة سياسته مع الـnormalizer (إعادة الأعطال العابرة بلا حد)، وتثبيت مجمّع، ومعالجة rebalance.

**ADIS-P01-010**
- **الخطورة:** MEDIUM
- **المكوّن:** الوكيل (`spool.py`)
- **المشكلة:** ملف spool تالف يرمي `sqlite3.DatabaseError` غير مُعالَج (رمز الخروج 1)، والوكيل لا يعمل حتى تدخل يدوي.
- **الأثر:** توقف جمع البيانات على المضيف، ولا إرشاد للمشغل.
- **الدليل:** فحص spool التالف؛ `spool.py:109`؛ `__main__.py:64` يلتقط `ConfigurationError` و`IdentityError` فقط.
- **التوصية:** التقاط الخطأ، ونقل الملف إلى `spool.corrupt-<ts>`، وتسجيل فقدان واضح، ثم متابعة التشغيل. أو على الأقل رسالة ورمز خروج مخصصان مع توثيق.

**ADIS-P01-011**
- **الخطورة:** MEDIUM
- **المكوّن:** الإعدادات والأمان
- **المشكلة:** الإنتاج يسمح بـ`KAFKA_SECURITY_PROTOCOL=PLAINTEXT` وبـ`DB_SSL_MODE=disable`/`prefer`، وSASL غير مدعوم.
- **الأثر:** إمكانية نشر إنتاجي بلا تشفير للقياس عن بُعد وبيانات الاعتماد.
- **الدليل:** `sections.py:155,182`؛ `clients.py` يرفض SASL؛ OD-5 وOD-10 وOD-12.
- **التوصية:** رفض PLAINTEXT و`disable`/`prefer` عند `APP_ENV=production`، ودعم SASL/SCRAM.

**ADIS-P01-012**
- **الخطورة:** MEDIUM
- **المكوّن:** اختبارات تكامل الـnormalizer
- **المشكلة:** `migrated_database` ينفّذ `TRUNCATE` لمصدر الحقيقة، ثم تقرأ الاختبارات التاريخ الخام بمجموعات جديدة، فتعيد نشر آلاف الأحداث إلى `adis.security.events` في كل تشغيل.
- **الأثر:** تضخم غير محدود للوسيط المشترك (39,653 سجلاً)، وهذا يسبب ADIS-P01-002، ويبطئ كل تشغيل لاحق.
- **الدليل:** `tests/integration/database/conftest.py` (`TRUNCATE`)؛ `tests/integration/normalizer/test_normalizer.py` (`unique_group`).
- **التوصية:** مواضيع أو بادئات معزولة لكل تشغيل، أو قراءة من الإزاحة الحالية، أو تنظيف الوسيط في الـfixture.

**ADIS-P01-013**
- **الخطورة:** MEDIUM
- **المكوّن:** إزالة التكرار (الأمان)
- **المشكلة:** تكرار `event_id` بمحتوى مختلف يُسقط بصمت. معرّفات أحداث سجلات الوكيل حتمية (UUIDv5)، والرموز غير مربوطة بـ`agent_id`.
- **الأثر:** حامل رمز استيعاب يستطيع «حجز» معرّف حدث مستقبلي فيخفي الحدث الحقيقي، دون أي إشارة.
- **الدليل:** `repositories/security_events.py:101`؛ OD-16 وOD-20.
- **التوصية:** ربط الرمز بالوكيل، ومقارنة محتوى التكرار بالمخزن ورفع إشارة سلامة عند الاختلاف.

### LOW

**ADIS-P01-014**
- **الخطورة:** LOW
- **المكوّن:** المخطط القياسي
- **المشكلة:** الطوابع المستقبلية مقبولة بلا حد (+365 يوماً)، وكذلك القديمة جداً. المنفذ 0 مقبول.
- **الأثر:** جودة بيانات، وإمكانية إخفاء أحداث عن نوافذ زمنية.
- **الدليل:** فحص edge؛ `v1.py:192`.
- **التوصية:** حد انحراف ساعة قابل للإعداد يُعلِّم الحدث أو يرفضه.

**ADIS-P01-015**
- **الخطورة:** LOW
- **المكوّن:** `packages/kafka`
- **المشكلة:** طلب إيقاف قبل بدء `run()` يضيع.
- **الأثر:** إيقاف لا يُنفَّذ في حالات حافة.
- **الدليل:** `consumer.py:236` و`batch_consumer.py:131`؛ OD-23.
- **التوصية:** مسح العَلَم عند نهاية `run()` بدل بدايته.

**ADIS-P01-016**
- **الخطورة:** LOW
- **المكوّن:** المستودع
- **المشكلة:** هياكل فارغة وإعدادات غير موصولة (§18)، و`CLAUDE.txt` مكرر.
- **الأثر:** ضجيج وتوقعات خاطئة.
- **الدليل:** §4.
- **التوصية:** توثيقها صراحة كـplaceholders أو إزالتها.

**ADIS-P01-017**
- **الخطورة:** LOW
- **المكوّن:** التوثيق
- **المشكلة:**
  - README وIMPLEMENTATION_STATUS يعلنان المرحلة 1 «Complete»، خلافاً لهذا التدقيق.
  - مثال docstring قديم في `packages/config/__init__.py:8`.
  - جدول البنية المحلية لا يذكر `postgres-test`.
  - لا دليل موحد لتشغيل المسار محلياً.
- **الأثر:** تضليل للمطورين.
- **الدليل:** §18.
- **التوصية:** تحديث الحالة بعد إغلاق النتائج العالية، وإضافة دليل «Run the pipeline locally».

**ADIS-P01-018**
- **الخطورة:** LOW
- **المكوّن:** الـAPI
- **المشكلة:** لا حد للطلبات المتزامنة (`limit_concurrency`)، والمحدد داخل العملية فقط (OD-17).
- **الأثر:** ضغط ذاكرة تحت حمل مرتفع؛ الميزانية تتضاعف مع عدد النسخ.
- **الدليل:** `__main__.py` لا يمرر `limit_concurrency`؛ `rate_limit.py`.
- **التوصية:** حد تزامن، ومحدد Redis بعد ADIS-P01-001.

**ADIS-P01-019**
- **الخطورة:** LOW
- **المكوّن:** السجلات
- **المشكلة:** stack trace كامل على مستوى ERROR لكل 503.
- **الأثر:** ضجيج أثناء الانقطاعات.
- **الدليل:** `api.log` (16 سطراً بـ`api_publish_failed` مع stacktrace).
- **التوصية:** WARNING مع نوع الخطأ فقط، وtrace عند DEBUG.

**ADIS-P01-020**
- **الخطورة:** LOW
- **المكوّن:** المستودع (قاعدة البيانات)
- **المشكلة:** لا cursor pagination، و`limit ≤ 1000` فقط.
- **الأثر:** الصفحات ممكنة بالنوافذ الزمنية فقط.
- **الدليل:** `repositories/security_events.py`.
- **التوصية:** keyset pagination بـ(`timestamp`, `id`).

**ADIS-P01-021**
- **الخطورة:** LOW
- **المكوّن:** Docker
- **المشكلة:** كلمة مرور Redis في سطر أوامر `redis-server`. compose يطلب كل الأسرار حتى لتشغيل خدمة واحدة.
- **الأثر:** ظهور كلمة المرور في قائمة العمليات داخل الحاوية؛ احتكاك للمطورين.
- **الدليل:** `docker-compose.yml` (خدمة redis).
- **التوصية:** ملف إعداد أو `REDISCLI_AUTH` مع `requirepass` من ملف، وملفات env منفصلة لكل profile.

**ADIS-P01-022**
- **الخطورة:** LOW
- **المكوّن:** الوكيل
- **المشكلة:** صلاحيات مجلد البيانات على Windows غير مضبوطة، والـspool غير مشفّر.
- **الأثر:** قراءة القياس عن بُعد المحلي من مستخدمين آخرين على المضيف.
- **الدليل:** OD-19.
- **التوصية:** ACLs على Windows، وتقييم التشفير.

---

## 20. Phase Completion Decision — قرار اكتمال المرحلة

| السؤال | الجواب |
|---|---|
| **هل المرحلة 0 مكتملة؟** | **NO**. الخطوة 0.4 (Redis) غير منفذة، ولا CI ولا git |
| **هل المرحلة 1 مكتملة؟** | **NO**. المسار يعمل ومتين، لكن معايير حرجة غير مستوفاة كاملة (أدناه) |
| **هل يمكن الانتقال بأمان إلى المرحلة 2؟** | **NO** |

### مراجعة معايير القبول الحرجة

| المعيار | الحالة |
|---|---|
| الـAPI يقبل الأحداث الصالحة | ✅ |
| غير الصالح يُرفض أو يُرسل إلى DLQ | ✅ |
| الصالح يصل إلى Kafka | ✅ |
| المستهلك يستقبل | ✅ |
| الـnormalizer ينتج أحداثاً قياسية | ✅ |
| الصالح يصل إلى `adis.security.events` | ✅ |
| الأحداث تُحفظ في Supabase | ⚠️ على PostgreSQL 17 فقط؛ Supabase الفعلي **UNVERIFIED** (ADIS-P01-004) |
| تفرّد `event_id` يمنع التكرار المنطقي | ✅ (قيد قاعدة بيانات) |
| إعادة تسليم Kafka لا تنتج صفوفاً مكررة | ✅ |
| الإزاحات لا تُثبَّت بطريقة تفقد أحداثاً | ✅ |
| فشل القاعدة لا يفقد أحداثاً | ✅ |
| فشل Kafka لا يعلن نجاحاً كاذباً | ✅ |
| الرسائل التالفة مُعالَجة | ✅ |
| تدفق DLQ يعمل | ✅ |
| لا أسرار مضمّنة | ✅ |
| مفتاح Service Role غير مكشوف للواجهة | ✅ (لا كود واجهة) |
| السجلات المنظمة تعمل | ✅ |
| `trace_id` و`event_id` قابلان للتتبع عبر المسار | ⚠️ **PARTIAL** (ADIS-P01-005) |
| دورة الإقلاع والإيقاف آمنة | ⚠️ آمنة بلا فقدان، لكن لا تتعافى ذاتياً عند الإقلاع (ADIS-P01-007) |
| الاختبارات الحرجة تعمل فعلاً | ❌ تُتخطى افتراضياً، ولا CI، واختبار تكامل يفشل (ADIS-P01-002 وADIS-P01-003) |

### القضايا المانعة (Blocking issues)

1. **ADIS-P01-001:** Redis (الخطوة 0.4) غير منفذ.
2. **ADIS-P01-002:** حزمة الاختبارات ليست خضراء (اختبار تكامل يفشل حسب كمية البيانات).
3. **ADIS-P01-003:** الاختبارات الحرجة تتخطى افتراضياً، ولا CI، ولا git.
4. **ADIS-P01-004:** لم يُتحقق من الحفظ على Supabase الفعلي.
5. **ADIS-P01-005:** التتبع جزئي في سجلات الـnormalizer وDLQ.
6. **ADIS-P01-007:** الخدمات لا تتعافى عند غياب Kafka لحظة الإقلاع، ولا مشرف عمليات.
7. **ADIS-P01-006:** سجل الوكلاء (`agents`) لا يُكتب أبداً. مانع لاكتمال متطلب «registration» في 1.4 و1.2.

> ملاحظة: هذا التدقيق لم يصلح أي مشكلة، حسب التعليمات. الإصلاحات تنتظر موافقتك.
