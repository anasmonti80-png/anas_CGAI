# مصفوفة دعم المنصات

| المنصة أو المجال | الحالة الحالية | دليل الاختبار | ما يلزم قبل الادعاء بالدعم |
|---|---|---|---|
| Windows endpoint/server | Untested | لا يوجد | مختبر مصرح، أحداث وسياق حماية واختبار فقد المصدر |
| macOS | Untested | لا يوجد | entitlement، System Extension، سياسة خصوصية واختبارات توافق |
| Linux | Untested | لا يوجد | توزيعات وkernel وصلاحيات وتكلفة حساس واختبارات تعطّل |
| Active Directory / Entra | Untested | لا يوجد | حساب قراءة منفصل وعينات مختبرية ونموذج ثقة هوية |
| شبكة / NCC | Integration required | لا يوجد | API مصادق ونطاق وموافقة وتحقق وتراجع؛ لا تنفيذ مباشر |
| AWS / Azure / GCP / SaaS | Untested | لا يوجد | موصلات read-only وحسابات مختبر ومناطق وتكلفة وحدود API |
| SIEM / EDR / NDR | Untested | لا يوجد | عقد مخطط وإصدار موصل وعينات دليل واختبارات قبول |

`Untested` و`Integration required` لا يعنيان Unsupported دائمًا، ولا يجيزان عرض دعم أو منع أو تغطية فعلية.

