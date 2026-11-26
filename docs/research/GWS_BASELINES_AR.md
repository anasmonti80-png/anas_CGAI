# دراسة: خطوط أساس أمان Google Workspace مقارنةً بـ Microsoft 365 (CG-147)

تاريخ المراجعة: 2026-11-26. المصادر رسمية فقط، وتُذكر في آخر الدراسة.

## الأداة والمرجع

- خطوط أساس CISA SCuBA لـ Google Workspace تُفحص بأداة **ScubaGoggles**، وآخر إصدار عند المراجعة **1.1.0**.
- خطوط الأساس المنشورة:
  - Common Controls.
  - Gmail.
  - Drive and Docs.
  - Calendar.
  - Chat.
  - Meet.
  - Groups for Business.
  - Sites.
  - Classroom.
  - Assured Controls.
  - Gemini (تجريبي).
- مخرجات الأداة تتبع مخطط ScubaGear نفسه، وفيه المفاتيح `MetaData` و`Summary` و`Results` و`Raw`. ولكل ضابط الحقول `Control ID` و`Requirement` و`Result` و`Criticality` و`Details`.
- لذلك يستخدم CyberGuard المحلل نفسه للأداتين (`parseScuba`)، ويختلف بينهما بادئة المعرّف فقط: `GWS.*` لـ Google و`MS.*` لـ Microsoft.
- قيم `Result` الإضافية في ScubaGoggles:
  - **`No events found`**: الفحص مبني على سجلات الإدارة ولم يجد حدثًا.
  - **`Incorrect Result`**: نتيجة وسمها المالك بأنها غير صحيحة.
- إصدار السياسة قد يكون عشريًا (مثل `GWS.CALENDAR.3.2v0.5`)، ويُحتفظ به كما هو.

## الصلاحيات الفعلية

- تتطلب ScubaGoggles دور **Super Admin**. هذا أعلى من دور Global Reader الكافي في ScubaGear، فهو فرق جوهري بين المنصتين.
- تطلب الأداة 11 نطاق OAuth:
  - **9 منها للقراءة فقط** (`*.readonly`).
  - نطاقان بلا شكل قراءة فقط: `apps.licensing` و`apps.groups.settings`.
  - وتذكر الأداة أن واجهة إعدادات المجموعات لا تدعم نطاق قراءة فقط أصلًا، فتستخدم دور Groups Reader عبر حساب خدمة بتفويض إداري.
- الواجهات المستخدمة:
  - Admin SDK.
  - Groups Settings.
  - Cloud Identity، وتعتمد عليها معظم الفحوص عبر Policy API.
  - Enterprise License Manager، لبيانات الترخيص.
  - Reports API، لفحوص سجلات الإدارة.
- **التوصية:** حساب إداري مخصص ومراقَب للتشغيل فقط، وإلغاء عميل OAuth بعد كل تشغيل. CyberGuard نفسه لا يحمل أي اعتماد لـ Google.

## حدود الواجهات والتراخيص

- **الفحوص المبنية على السجل:**
  - لا ترى إعدادًا لم يُغيَّر قط عن قيمته الافتراضية.
  - سجلات الإدارة تمتد نحو ستة أشهر فقط.
  - الوحدات التنظيمية الفرعية بلا أحداث يُفترض أنها ترث الإعداد من الأصل، والأداة نفسها تقول إن ذلك ليس مضمونًا.
  - لذلك تظهر «لا أحداث في السجل — الإعداد غير مثبت»، ولا تُحتسب مطابقة.
- **الترخيص:**
  - خطوط الأساس الثلاثة (Common Controls وGmail وDrive) تفترض صراحة إصدار **Enterprise Plus**، وتنبّه إلى أن بعض الإعدادات غير متاحة في كل الإصدارات.
  - الوصول حسب السياق (Context-Aware Access) موثّق لإصدارات Frontline Standard/Plus وEnterprise Standard/Plus وEducation Standard/Plus وEnterprise Essentials Plus. والمستخدم دون إصدار مدعوم لا تنطبق عليه سياساته.
  - منع تسرب البيانات (DLP) موثّق لإصدارات منها Frontline Standard وEnterprise Standard وEnterprise Plus. والقائمة في المصدر أطول، لذلك تُعامل الإصدارات خارجها بحذر: يُطلب التأكد منها ولا يُحكم عليها.
- **القاعدة:** يعلن المالك إصدار الترخيص عند الاستيراد.
  - الضابط الذي يحتاج ميزة غير موثقة للإصدار المعلن يصبح «يعتمد على الترخيص» بدل «انحراف»، ولا يطلق تنبيهًا.
  - الإصدار غير المعلن لا يُفترض أنه Enterprise Plus أبدًا.

## المقارنة مع Microsoft 365 في المجالات الأربعة

| المجال | Google Workspace | Microsoft 365 | ملاحظة |
|---|---|---|---|
| التحقق متعدد العوامل | `GWS.COMMONCONTROLS.1` (MFA مقاوم للتصيد، منع SMS/الصوت، مدة تسجيل 2SV، منع «الثقة بالجهاز») | `MS.AAD.3` | كلاهما يشترط MFA مقاومًا للتصيد بمستوى «يجب». في Google يُقاس لكل وحدة تنظيمية، وفي Entra عبر سياسات الوصول المشروط. |
| المشاركة الخارجية | `GWS.DRIVEDOCS.1` (قائمة نطاقات مسموحة، تحذيرات، «أي شخص لديه الرابط»، النماذج الخارجية) | `MS.SHAREPOINT.1` | بعض ضوابط النماذج يدوية في ScubaGoggles، فيبقى المجال «غير مثبت» حتى التحقق اليدوي. |
| البريد | `GWS.GMAIL.1` (التفويض)، `GWS.GMAIL.11` (إعادة التوجيه التلقائي)، `GWS.GMAIL.12` (بوابات صادرة لكل مستخدم)، `GWS.GMAIL.14` (قوائم السماح) | `MS.EXO.1` (إعادة التوجيه إلى نطاقات خارجية) | إعادة التوجيه التلقائي في Google بمستوى «ينبغي»، وفي Exchange Online بمستوى «يجب». |
| التطبيقات الخارجية | `GWS.COMMONCONTROLS.10` و`11` (التحكم بوصول التطبيقات إلى الواجهات، منع التطبيقات غير المهيأة، Marketplace المعتمد) | `MS.AAD.5` (تسجيل التطبيقات والموافقة عليها) | قارن مع مخزون OAuth في CG-142 لمعرفة التطبيقات الموافق عليها فعلًا. |

تُعرض المقارنة في صفحة الهوية لكل نطاق Google مقابل آخر استيراد لـ Microsoft 365. والمجال الذي لم يُقيَّم في إحدى المنصتين يظهر «لم يُقيَّم»، ولا يُستنتج عنه شيء.

## المصادر

- https://github.com/cisagov/ScubaGoggles
- https://github.com/cisagov/ScubaGoggles/blob/main/docs/misc/tooloutputschema.md
- https://github.com/cisagov/ScubaGoggles/blob/main/docs/prerequisites/Prerequisites.md
- https://github.com/cisagov/ScubaGoggles/blob/main/docs/usage/Limitations.md
- https://github.com/cisagov/ScubaGoggles/tree/main/scubagoggles/baselines
- https://support.google.com/a/answer/9275380
- https://github.com/cisagov/ScubaGear
