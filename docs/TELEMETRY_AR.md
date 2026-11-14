# عقد استقبال الأدلة cg.telemetry/1

`POST /api/sources/{source-id}/events` مع `Authorization: Bearer <source-token>` و`Content-Type: application/json`. واجهة الاستيراد تستخدم جلسة المسؤول/المحلل وCSRF بدل رمز المصدر. لكل مصدر namespace مستقل؛ لا يجوز استخدام مفتاحه لمصدر آخر.

```json
{
  "schema_version": "cg.telemetry/1",
  "events": [
    {
      "event_id": "unique-within-source",
      "kind": "asset.observed",
      "observed_at": "2026-11-11T10:00:00.000Z",
      "asset": {
        "external_id": "source-device-id",
        "hostname": "SYNTHETIC-EXAMPLE",
        "os_family": "unknown",
        "device_type": "unknown",
        "addresses": ["192.0.2.10"]
      },
      "details": {}
    }
  ]
}
```

المثال اصطناعي ولا يُستورد تلقائيًا. أقصى دفعة 250 حدثًا و2 MB. وقت ISO UTC بعد 2000، بحد انحراف مستقبلي خمس دقائق. تكرار المعرف والمحتوى = duplicate؛ تكرار المعرف بمحتوى مختلف = رفض 409 للدُفعة كاملة. أي حقل غير مدعوم مرفوض؛ لا أوامر أو scripts في العقد.

| kind | details |
|---|---|
| asset.observed | `{}` |
| auth.failed | account اختياري، source_ip اختياري، protocol: rdp/ssh/winrm/web/unknown |
| protection.observed | engine، installed/running/collecting منطقيات، mode: active/passive/unknown |
| remote.port_open | evidence_type: port_observation |
| remote.attempt | evidence_type: connection_attempt |
| remote.authenticated | evidence_type: authentication_log |
| remote.active / remote.ended | evidence_type: session_log |
| security.finding | title، description، severity: critical/high/medium/low/info |

كل remote يحتوي أيضًا session_id فريدًا حسب الجهاز ومدة إقلاع/جلسة المنتج، protocol: rdp/ssh/winrm/anydesk/teamviewer/apple-remote-desktop/vpn/other، وsource_a وtarget_b (كل منهما hostname/ip/account اختيارية)، وrelay منطقيًا. خلف relay لا يُنسب المصدر إلى A دون دليل مستقل؛ النسخة الحالية تجعل A مجهولًا تحفظًا. انتهاء جلسة أو authentication لا يثبت active control؛ الحقول الدقيقة تتبع ما قدمه المصدر.

النصوص الحساسة المعروفة تُنقح قبل التخزين، لكن هذا ليس بديلًا عن تقليل البيانات في الموصل. يُخزن hash الأصل وhash النسخة المنقحة منفصلين. لا توجد صيغة raw logs مفتوحة، ولا يُدّعى توافق OCSF بهذه الصيغة. الملف JSON محلي؛ ليست الواجهة listener لـSyslog/NetFlow أو Agent دائمًا.

## استيراد Windows Security

الواجهة وendpoint نفسه يقبلان `cg.windows-export/1`. يوفر `scripts/Export-WindowsEvents.ps1` تصديرًا يدويًا للقراءة فقط من السجل المحلي، إذا كانت صلاحية قراءة Security متاحة أصلًا. لا يرفع الصلاحيات أو يفعّل auditing، ولا يرفع الملف إلى الخادم. لا تشغّله من مهام دورية تلقائيًا في هذا الإصدار. يفحص صلاحية قراءة سجل Security أولًا: إذا لم تكن متاحة يتوقف برسالة صريحة بأن ذلك ليس دليلًا على عدم وجود تسجيلات دخول (ويندوز يجيب عن الاستعلام المفلتر بـ«لا توجد أحداث» عند المنع)، وإذا كان السجل مقروءًا دون أحداث مطابقة يذكر ذلك والنافذة الزمنية، ولا يُنشئ ملفًا في الحالتين.

```powershell
# اختر مسارًا جديدًا داخل مجلد خاص موجود على جهازك.
.\scripts\Export-WindowsEvents.ps1 -OutputPath 'C:\PrivateTelemetry\security-export.json' -Hours 1 -MaxEvents 200
```

استورد الملف من مصدر مسمى في الواجهة. الحدود 250 سجلًا و2 MB. الحقول: `schema_version`, `computer`, `boot_time`, `events`. كل سجل يحتوي `event_id`, `record_id`, `time_created`, `provider`, `channel`, `data`. المزود المقبول `Microsoft-Windows-Security-Auditing` والقناة `Security` فقط؛ يتم تصدير قائمة صغيرة من حقول EventData بدل محتوى XML الكامل.

| الحدث | النتيجة | حدود الاستدلال |
|---|---|---|
| 4624 + LogonType 10 | remote.authenticated | مصادقة RDP مبلغ عنها؛ لا يثبت التحكم النشط |
| 4634 + LogonType 10 | remote.ended | انتهاء جلسة مسندة لنفس الجهاز والإقلاع ومعرف الدخول |
| 4625 | auth.failed | IP مجهول عند غيابه؛ نوع 10 يصنف RDP فقط |
| غير المدعوم أو logon غير بعيد | مستبعد بتقرير ظاهر | لا تحويل قسري إلى جلسة بعيدة |

`TargetUserName` يصف حساب الهدف B؛ لا يُنسب إلى A. اسم/IP المصدر يبقيان مجهولين إذا لم يقدمهما السجل. معرّف الجلسة يشمل بصمة وقت الإقلاع لأن Logon ID قد يعاد استخدامه بعد إعادة الإقلاع. يُرفض حدث أقدم من الإقلاع المعلن. يعرض رد الاستيراد `parser_report` وعدد المستبعد. أي سجل مخالف للعقد يرفض الدفعة كاملة؛ الدفعة التي لا تحتوي أي حدث مدعوم مرفوضة أيضًا.

يحفظ `origin` إصدار `windows-security/1` وrecord_id وبصمة السجل المصدر إلى جانب بصمات الحدث المنقح. هذه بصمة لحقول JSON المصدرة، وليست بصمة EVTX الأصلي أو توقيعًا من Windows. تغيير اسم الجهاز قد ينشئ أصلًا جديدًا؛ لا يوجد ربط أجهزة موثق عابر للمصادر. المحوّل **Unit Tested** بعينات اصطناعية؛ سكربت PowerShell اجتاز فحص الصياغة فقط ولم يشغّل على سجل أمني حقيقي.

دلالة الحقول مبنية على توثيق Microsoft: [4625 — failed logon](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)، و[4634 — logoff](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634). لا يشمل هذا المحوّل Sysmon أو Defender أو AnyDesk أو TeamViewer.

## قواعد الإصدار

خمس محاولات دخول فاشلة خلال خمس دقائق لنفس المصدر/الأصل/الحساب/IP تنتج تنبيهًا. حماية مبلغ عنها مثبتة ومتوقفة تنتج تنبيهًا. منفذ وصول بعيد ينتج Exposure فقط. security.finding يبقى تقرير مصدر، لا إثبات استغلال. مصدر لا يستقبل خلال stale_seconds ينتج Lost Coverage. التنبيهات تُجمع لكل مفتاح/يوم، وإعادة occurrence تفتحها لإقرار جديد. الأدلة الأخيرة حتى 100 مرجع في التنبيه، بينما جميع الأحداث محفوظة في جدولها.

## الاكتشاف المتسلسل المحلي (CG-006)

يقرأ `scripts/Export-LocalDiscovery.ps1` ما يعرفه جهاز Windows نفسه فقط: ذاكرة ARP وذاكرة DNS وإعداد DHCP والبوابة، ولا يرسل أي حزمة أو يغيّر أي إعداد. يُقرأ AD فقط مع `-IncludeActiveDirectory` على جهاز منضم لنطاق. تظهر LLDP/CDP وSNMPv3 وAPI «غير متاحة» مع السبب حتى يتوفر مجمّع مصرح به. الناتج ملف `cg.telemetry/1` يُرسل يدويًا إلى مصدر بيانات.

```powershell
.\scripts\Export-LocalDiscovery.ps1 -OutputPath 'C:\PrivateTelemetry\discovery.json' -AuthorizationRef 'APPROVED-SCOPE-REF'
```
