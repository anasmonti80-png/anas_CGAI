# CyberGuard AI (CG AI) — V3.0

**Enterprise cybersecurity research and engineering specification — مواصفات مشروع سايبر جارد AI**

> **الحالة:** بدأ التنفيذ، وتوجد نسخة هندسية محلية **0.1.0** قابلة للتشغيل. المنصة ليست جاهزة للإنتاج ولم تكتمل المتطلبات **1,440**. النصوص التاريخية محفوظة حرفيًا، والتغطية الجزئية لا تُحسب قبولًا كاملًا.

## تشغيل النسخة الهندسية

يلزم Node.js **24.21.0 أو أحدث ضمن 24**؛ لا يلزم `npm install`.

```text
node scripts/launch.js
```

على Windows يمكن تشغيل `START_CYBERGUARD.cmd`. افتح `http://127.0.0.1:4310`، واستخدم رمز التهيئة من ملف `data/setup-token` المحلي لإنشاء حسابك؛ لا كلمة مرور افتراضية. [دليل التشغيل](docs/OPERATIONS_AR.md).

المتاح: واجهة عربية/إنجليزية، إعداد ومصادقة وأدوار، جرد وأدلة، استيراد JSON وWindows Security، قواعد محلية وتنبيهات وتحقيقات، تتبع جلسات A→B، موافقة مستقلة وتراجع لتغيير أهمية الأصل محليًا، وسجل تدقيق. لا ينفّذ إجراءات أجهزة أو شبكة، ولا يحتوي محرك LLM أو منع EDR.

```text
node scripts/verify.js
node scripts/requirements.js
```

[نتائج الاختبارات](artifacts/verification.json) · [سجل التحقق والقيود](docs/engineering/VALIDATION_AR.md) · [دعم المنصات](docs/engineering/SUPPORT_MATRIX.json) · [عقد البيانات](docs/TELEMETRY_AR.md) · [خطة استكمال النطاق](docs/engineering/MILESTONES_AR.md).

## البداية مع Codex

1. اقرأ [AGENTS.md](AGENTS.md) و[دليل البدء في Codex](00_START_HERE/CODEX_START_HERE.md).
2. اقرأ [برومبت التنفيذ](00_START_HERE/CyberGuard_AI_V3.0_EXECUTION_PROMPT_ONLY.md).
3. استخدم [البرومبت الرئيسي الكامل](00_START_HERE/CyberGuard_AI_V3.0_MASTER_PROMPT_COMPLETE.md).
4. راجع [كل المتطلبات كـ JSONL](02_REQUIREMENTS/CG_Requirements_1440.jsonl)، ثم [تقسيمات الـ12 ملفًا](02_REQUIREMENTS/CHUNKS/).
5. راجع [تقرير إغلاق الفجوات](01_SOURCE/Gap_Closure_Audit_v2.9.md) و[السجل الأخير v2.9](01_SOURCE/Research_and_Requirements_v2.9.md).
6. احتفظ بمراجعات [تاريخ المشروع من v0.3 إلى v2.9](03_HISTORY/).

[مهمة بدء التطوير على GitHub](../../issues/1) توثق أول مخرجات مطلوبة من Codex.

## نطاق المشروع

- حماية الأجهزة والخوادم على Windows وmacOS وLinux وفق قدرات كل نظام وإصداره.
- اكتشاف وتصنيف الأجهزة، والتحقق من حالة الحماية، وتطبيق ملفات حماية تكيفية.
- تحليل تهديدات وSIEM/XDR، ومراقبة جلسات التحكم عن بُعد مع التمييز بين جهاز المتحكم A والجهاز المستهدف B.
- AI Red Team واختبارات تحقق دفاعية *مصرح بها*؛ مع أدلة وموافقة بشرية مستقلة قبل أي إجراء حساس.
- أتمتة الاستجابة الأمنية، DevSecOps، أمن الهوية والسحابة، واختبارات التعافي.
- **NCC** لإدارة الشبكات، و**IT Twin** للتوأم الرقمي، ونظام **Tickets** لخدمات الصيانة تبقى مشروعات منفصلة.

## سلامة الملفات والتصميم

- المعرفات: **CG-001 إلى CG-1440**، تم التحقق من جميع سجلات JSONL دون فجوات.
- [Manifest V3.0](00_START_HERE/Manifest_V3.0.json) يضم بصمات SHA-256 للمستندات الرئيسية.
- أُضيفت [صورة التصميم الأصلية](04_REFERENCE/SOC_Dashboard_User_Reference.png) من ملف المستخدم، وتطابق بصمتها مرجع V3.0 تمامًا. تفاصيل الاستخدام في [دليل المرجع البصري](04_REFERENCE/README.md).
- لا ترفع إلى هذا المستودع بيانات تشغيل حساسة أو كلمات مرور أو مفاتيح API.

**تنبيه:** هذا المستودع عام حاليًا. يمكن تحويله إلى Private من إعدادات GitHub؛ النسخ التي حصل عليها الآخرون أثناء كونه عامًا لا يمكن استرجاعها بعد ذلك.
