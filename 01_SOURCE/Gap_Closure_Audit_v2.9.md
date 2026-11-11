# CyberGuard AI — تدقيق سد الفجوات v2.9

هذا الملخص مستقل، والسجل التراكمي في `CyberGuard_AI_Research_and_Requirements_v2.9.md`.



# مراجعة إغلاق الفجوات v2.9 — القرارات الهندسية وإثبات القبول (CG-1411–CG-1440)

**تاريخ الدراسة:** 10 نوفمبر 2026. **الحالة:** تحليل متطلبات وتوثيق رسمي فقط؛ لا برمجة، لا تشغيل فحص هجومي، ولا اختبار حقيقي على الأجهزة.

**التعريف الصحيح للإغلاق:** أغلقنا *فجوة القرار البحثي* عندما نحدد سلوك الميزة وحدودها ومصدرها وصلاحياتها واختبار قبولها. **فجوة إثبات التشغيل الفعلي تظل مفتوحة إلى أن تبدأ الهندسة ويُنفّذ الاختبار ويُراجع دليله**. لا توجد ضمانات 100% ضد كل التهديدات.

**القرار الحاكم للنطاق:** CyberGuard = Security Core + AIOps/SOAR + DevSecOps + Cyber Resilience + Security AI. NCC لإدارة الشبكات/السويتشات؛ IT Twin للتوأم الرقمي؛ Tickets للصيانة. CyberGuard يحلل أمن المنافذ ويقدم طلب احتواء عبر NCC فقط بموافقة، ولا يتحول إلى NMS أو ITSM.

## مصفوفة سدّ الفجوات العشر

| الرمز | الفجوة | نتيجة الحسم البحثي | ما لا يزال بحاجة لاختبار أو اختيار | متطلبات الإغلاق |
|---|---|---|---|---|
| G01 | محرك الحماية والتكامل | سلوك وصلاحيات ومعايير قبول مُعرّفة | مزود EDR/AV المدعوم وتراخيصه على كل OS؛ إثبات المنع | CG-1411–CG-1413 |
| G02 | توافق Windows وmacOS وLinux | سلوك وصلاحيات ومعايير قبول مُعرّفة | بناء مصفوفة لكل إصدار/نواة/صلاحيات Apple واختبارات الأداء | CG-1414–CG-1416 |
| G03 | الاكتشاف الشامل ودقة الهوية | سلوك وصلاحيات ومعايير قبول مُعرّفة | SNMP/AD/WLC/EDR موصلة فعليًا وقياس تغطية الشبكات | CG-1417–CG-1419 |
| G04 | AI Red Team والتحقق الآمن من الثغرات | سلوك وصلاحيات ومعايير قبول مُعرّفة | بيئة اختبار/تفويض فعلي وسيناريوهات غير مدمرة | CG-1420–CG-1422 |
| G05 | الإصلاح الذكي والموافقة والتراجع | سلوك وصلاحيات ومعايير قبول مُعرّفة | عقود API مع المنتجات، اختبار rollback وNCC | CG-1423–CG-1425 |
| G06 | حماية CyberGuard والأيجنتات | سلوك وصلاحيات ومعايير قبول مُعرّفة | اختبار استرجاع Control Plane وتوقيعات الأيجنت | CG-1426–CG-1428 |
| G07 | السجلات والتطبيع والصفارات | سلوك وصلاحيات ومعايير قبول مُعرّفة | عينات Logs فعلية؛ نسب فقد ومراقبة الاستلام | CG-1429–CG-1431 |
| G08 | التعافي والاستمرارية | سلوك وصلاحيات ومعايير قبول مُعرّفة | نسخ اختبار واستعادة نظام/بيانات مع RTO/RPO | CG-1432–CG-1434 |
| G09 | السحابة والخصوصية والسيادة | سلوك وصلاحيات ومعايير قبول مُعرّفة | اختيار مورد/منطقة وتقييم نقل البيانات والتراخيص | CG-1435–CG-1437 |
| G10 | جاهزية الإصدار وقابلية التشغيل | سلوك وصلاحيات ومعايير قبول مُعرّفة | بناء حالات CI والمصفوفة وأدلة الاختبار المستقلة | CG-1438–CG-1440 |

**حالة التحقق:** لا واحدة من هذه الفجوات «مُغلقة تشغيليًا». هي **محسومة بحثيًا بشرط** ويجب أن تحمل علامة Unverified حتى تُختبر.

## المتطلبات الجديدة — عقود قدرة دقيقة واختبارات إثبات

### G01 — محرك الحماية والتكامل

**قرار الدراسة:** لا نختار محرك AV/EDR واحدًا لكل البيئات، بل عقد قدرات يربط حماية أصلية/منتجًا مؤسسيًا/رصدًا مستقلًا. يمنع تثبيت محركين نشطين بصورة تلقائية.

**صلته بالمتطلبات الموجودة:** CG-010–013، CG-044، CG-1141–1188، CG-1301–1340.

- **CG-1411** — **Security Enforcement Owner Contract**: لكل جهاز حقل منفصل لـ primary prevention engine وEDR visibility وmanagement authority وحالات active/passive/unknown؛ منع ادعاء أن CyberGuard هو من منع الهجوم عندما يكون الطرف المنفذ منتجًا آخر. **دليل قبول مستقبلًا:** توليد تقرير لجهاز يحمل EDR خارجيًا؛ يظهر مصدر المنع الحقيقي؛ لا يتغير نمط الحماية تلقائيًا. **المرجع:** [MDE-AV](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility).
- **CG-1412** — **No Conflicting Protection Gate**: قاعدة منع تشغيل Real-time AV ثاني أو فلتر شبكة/ملفات متعارض قبل معرفة المحركات المثبتة وتوافق الإصدارات وشروط البائع. **دليل قبول مستقبلًا:** اختبار تعارض مفترض يرفض تفعيل المحرك الإضافي ويذكر السبب وخطة بديلة. **المرجع:** [MDE-AV](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility).
- **CG-1413** — **Evidence-Based Protection Claims**: تفريق صريح بين Installed / Running / Telemetry Healthy / Prevention Tested / Remediation Verified؛ لا يعرض Protected لمجرد وجود Agent. **دليل قبول مستقبلًا:** عينات ثلاث: برنامج مثبت متوقف، يعمل بلا سجلات، وقاعدة منع اجتازت اختبارًا؛ تظهر حالات مختلفة. **المرجع:** [MITRE-Evals](https://attackevals.mitre.org/enterprise/er8).

### G02 — توافق Windows وmacOS وLinux

**قرار الدراسة:** نحدد دعم الخاصية عبر OS/version/architecture/kernel/extension privileges/vendor license؛ ونوضح حالات degrade/unsupported.

**صلته بالمتطلبات الموجودة:** CG-1189–1236، CG-1237–1268، CG-1410.

- **CG-1414** — **Per-OS Capability Ledger**: ملف توافق مستقل يتضمن Windows client/server/build، macOS/Apple Silicon/Intel/EndpointSecurity entitlement، وLinux distro/kernel/BTF/driver، مع تاريخ آخر إثبات. **دليل قبول مستقبلًا:** عند تبديل Linux kernel لإصدار غير مدعوم يتغير تصنيف kernel sensor إلى Unsupported دون تعطل لوحة التحكم. **المرجع:** [Tetragon](https://tetragon.io/docs/installation/faq/).
- **CG-1415** — **No Entitlement Bypass on macOS**: دعم مراقبة macOS المتقدمة فقط بالـEndpoint Security entitlement وموافقات النظام وتوزيع المؤسسة المدعوم، دون تجاوز SIP أو حيل نواة على الإنتاج. **دليل قبول مستقبلًا:** بدون entitlement يظهر Permission Required وتستمر وظائف الجرد المدعومة فقط. **المرجع:** [Apple-ES](https://developer.apple.com/documentation/bundleresources/system-extensions).
- **CG-1416** — **Rollout Ring and Resource Budget**: فحص الموارد وأثر التثبيت قبل التعميم باستخدام مجموعات اختبار ثم إطلاق مرحلي وقابل للتراجع؛ تعريف سقوف CPU/RAM/disk/network حسب نوع جهاز. **دليل قبول مستقبلًا:** اختبار ضغط اصطناعي: تجاوز الحد يوقف فحوصًا غير حرجة وينذر؛ لا يسقط وظيفة كشف حرجة بصمت. **المرجع:** [NIST-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final).

### G03 — الاكتشاف الشامل ودقة الهوية

**قرار الدراسة:** نربط الأدلة ولا نخلط بين الجهاز ومصدر IP/relay، ونظهر blind spots وأجهزة unmanaged.

**صلته بالمتطلبات الموجودة:** CG-005–009، CG-797–804، CG-1301–1340، CG-1381–1410.

- **CG-1417** — **Temporal Asset Identity Graph**: ربط IP/MAC/AD device ID/agent ID/DHCP lease/switch FDB/LLDP بزمن ومصدر ودرجة ثقة؛ MAC وIP ليسا هوية وحيدة ولا يثبتان الشخص. **دليل قبول مستقبلًا:** إذا أعيد استخدام عنوان DHCP لا تُدمج هوية الجهازين في سجل أصل واحد. **المرجع:** [Netdisco](https://github.com/netdisco/netdisco).
- **CG-1418** — **Switch Port Provenance and Ambiguity**: التمييز بين physical edge port وuplink وvirtual interface والجهاز خلف NAT/VoIP phone/mini-switch، مع دليل موقع المنفذ وتاريخ القراءة. **دليل قبول مستقبلًا:** جهاز خلف سويتش غير مدار يصنف last known upstream port لا منفذ الجهاز النهائي المؤكد. **المرجع:** [Netdisco](https://github.com/netdisco/netdisco).
- **CG-1419** — **Visibility Coverage Manifest**: خريطة مصادر الاكتشاف: Agent/AD/DHCP/NAC/SNMP/Flow/Wi-Fi/WLC؛ إظهار الأجهزة غير المفحوصة والمناطق المعتمة والحد الأقصى للرؤية من PC. **دليل قبول مستقبلًا:** فصل حساس Wi-Fi أو حذف صلاحية SNMP يرفع Blind Spot وليس 0 Threats. **المرجع:** [NIST-ZT](https://csrc.nist.gov/pubs/sp/800/207/final).

### G04 — AI Red Team والتحقق الآمن من الثغرات

**قرار الدراسة:** نفصل تحليل ثغرة من الاستغلال المؤكد؛ لا brute force لحسابات حقيقية، ولا payload مؤثر على الإنتاج دون بيئة مخبرية وتفويض محدد.

**صلته بالمتطلبات الموجودة:** CG-024–028، CG-1341–1380.

- **CG-1420** — **Exploitability Evidence Grades**: درجات ثابتة: Exposure Seen / Misconfiguration Confirmed / Safe Simulation Passed / Lab Exploit Proven / Production Exploit Proven under separate authorization؛ مع حفظ الدليل. **دليل قبول مستقبلًا:** وجود منفذ 3389 وحده يعطي Exposure فقط وليس Compromised. **المرجع:** [MITRE-Caldera](https://www.mitre.org/our-impact/intellectual-property/caldera).
- **CG-1421** — **Validation Scope Token**: كل تقييم نشط يحتاج نطاق IP/asset محدد، مالك موافق، مدة، شدة الاختبار، آلية إيقاف، منع استهداف AD Tier 0 والمعدات الحساسة افتراضيًا. **دليل قبول مستقبلًا:** عنوان خارج التفويض أو انتهاء المدة يوقف الاختبار حتى إذا اقترحه AI. **المرجع:** [MITRE-Caldera](https://www.mitre.org/our-impact/intellectual-property/caldera).
- **CG-1422** — **No-Credential-Harvesting Validation**: اختبار سياسات كلمة المرور من إعدادات الهوية وبيانات اختبار اصطناعية أو حسابات مختبر مع حدود محاولات صغيرة؛ لا استخراج كلمات مرور أو تعطيل حسابات الموظفين. **دليل قبول مستقبلًا:** يكتشف غياب lockout/MFA من السياسة دون تعداد كلمات مرور حقيقية. **المرجع:** [NIST-Identity](https://csrc.nist.gov/pubs/sp/800/63/B/4/final).

### G05 — الإصلاح الذكي والموافقة والتراجع

**قرار الدراسة:** AI ينتج توصية ودليلًا فقط؛ محرك مستقل يتحقق من RBAC/MFA/scope/impact/approval ثم ينفذ إجراء typed/allowlisted ويراجع النتيجة.

**صلته بالمتطلبات الموجودة:** CG-029–035، CG-836، CG-1405–1408.

- **CG-1423** — **Typed Remediation API Only**: لا shell عام ولا API wildcard من نموذج AI؛ كتالوج typed actions محدد الإصدار ومختوم بمخطط بيانات، مع منع التعليمات الواردة من السجلات من الاستحواذ على التنفيذ. **دليل قبول مستقبلًا:** سجل خبيث يطلب إغلاق Firewall لا ينتج أمرًا؛ يبقى نصًا غير موثوق ضمن التحقيق. **المرجع:** [OWASP-Agent](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html).
- **CG-1424** — **Preflight and Commit Window**: جلب config/state/version قبل القرار؛ ربط الموافقة ببصمة الحالة والمدة والنطاق؛ رفض التطبيق إذا تغيّرت الحالة أو expired approval. **دليل قبول مستقبلًا:** موافقة لإغلاق port X لا تسمح بإغلاق port Y أو تنفيذ الأمر بعد تغير حالة السويتش. **المرجع:** [OWASP-Agent](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html).
- **CG-1425** — **Postcondition and Recovery Owner**: الإجراء يعتبر Success فقط بعد تحقق من حالة الوجهة وحالة الخدمات واعتماد سجل التغيير؛ عند الفشل خطة Rollback صريحة أو تدخل بشري. **دليل قبول مستقبلًا:** Firewall API يرجع 200 لكن القاعدة لم تُطبّق => status Failed/Unverified، لا Success. **المرجع:** [NIST-IR](https://csrc.nist.gov/pubs/sp/800/61/r3/final).

### G06 — حماية CyberGuard والأيجنتات

**قرار الدراسة:** CyberGuard نفسه أصل Tier-0-like من حيث أثر صلاحياته؛ مفاتيح مستقلة، mTLS، شهادات قصيرة، سجل تدقيق مقاوم للعبث، أقل الامتيازات.

**صلته بالمتطلبات الموجودة:** CG-052–058، CG-812، CG-834–836، CG-1285–1292.

- **CG-1426** — **Agent and Collector Identity Lifecycle**: هوية تشفيرية منفصلة لكل Agent/Collector مع إصدار وإبطال وتدوير الشهادات ومنع استنساخ agent ID عبر جهاز آخر. **دليل قبول مستقبلًا:** عميل بشهادة مبطلة يفشل في إرسال أوامر أو بيانات على أنها من جهاز موثوق. **المرجع:** [NIST-ZT](https://csrc.nist.gov/pubs/sp/800/207/final).
- **CG-1427** — **Compromised Control Plane Recovery**: خطة إذا اختُرق خادم CyberGuard: تجميد الإجراءات، إبطال شهادات التنفيذ والتوكنات، تشغيل مسار تحذير مستقل، استعادة بيانات سليمة. **دليل قبول مستقبلًا:** محاكاة توقف/اختراق Control Plane توقف تغيير الأجهزة وتستمر التنبيهات المحلية وفق القدرات. **المرجع:** [NIST-IR](https://csrc.nist.gov/pubs/sp/800/61/r3/final).
- **CG-1428** — **Supply Chain Integrity for All Collectors**: قائمة SBOM للمنصة والأيجنتات والتبعيات ونقاط التحديث، والتحقق من توقيع الحزم والمصدر، وسياسة عدم نشر تحديث غير موثوق. **دليل قبول مستقبلًا:** تحديث معدّل بتوقيع غير صالح يُرفض ولا يوقف الأيجنت الحالي. **المرجع:** [CISA-SBOM](https://content.govdelivery.com/accounts/USDHSCISA/bulletins/422a7eb).

### G07 — السجلات والتطبيع والصفارات

**قرار الدراسة:** نحتفظ بالأصل immutable حيث يلزم، ونربط حدث OCSF بالمصدر؛ نقص السجلات يولد إنذار فشل رؤية وليس انعدام تهديد.

**صلته بالمتطلبات الموجودة:** CG-018، CG-068–130، CG-1041–1052، CG-1101–1140.

- **CG-1429** — **Schema Version and Raw Evidence Reference**: تطبيع OCSF بنسخة Schema ثابتة لكل حدث مع raw reference/hash، وفشل parse صريح؛ عدم محو خصائص المصدر المهمة. **دليل قبول مستقبلًا:** تغيير parser لا يغيّر الدليل الخام ولا يفقد Session ID. **المرجع:** [OCSF](https://github.com/ocsf/ocsf-schema).
- **CG-1430** — **Telemetry Health Service Objectives**: قياسات source heartbeat/event lag/loss/duplication/time skew/discard، وتنبيه مستقل إذا توقفت سلسلة التنبيه أو انتهت مدة احتفاظ المصدر. **دليل قبول مستقبلًا:** قطع Syslog عن سيرفر لمدة محددة ينشئ Lost Coverage لا Healthy. **المرجع:** [NIST-IR](https://csrc.nist.gov/pubs/sp/800/61/r3/final).
- **CG-1431** — **Incident Notification Proof**: تعريف Sent/Provider Accepted/Delivered/Acknowledged/Acted separately، مع بديل On-Call عند عدم الاستلام وفصل الأسرار عن محتوى Push. **دليل قبول مستقبلًا:** حالة SMTP Accepted دون ACK لا تغلق التنبيه ولا تعتبر حادثًا محلولًا. **المرجع:** [NIST-IR](https://csrc.nist.gov/pubs/sp/800/61/r3/final).

### G08 — التعافي والاستمرارية

**قرار الدراسة:** اختبار عزل/استعادة/تحقق خدمات وبيانات بهوية منفصلة وأهداف RTO/RPO واقعية.

**صلته بالمتطلبات الموجودة:** CG-857–866، CG-1293–1300، CG-859، CG-906.

- **CG-1432** — **Recovery Dependency Order**: خريطة ترتيب استعادة: DNS/AD/PKI والهوية ومخازن الأسرار وقواعد البيانات ثم التطبيق، مع استثناءات حسب بنية المؤسسة. **دليل قبول مستقبلًا:** خطة استعادة تقرّب فشل اعتماد التطبيق على DNS/AD وتحدد المسؤول قبل التنفيذ. **المرجع:** [NIST-BCP](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-34r1.pdf).
- **CG-1433** — **Clean-Room Restore Test Evidence**: اختبار استعادة من نقطة مختارة في بيئة معزولة، فحص سلامة الملفات والتطبيق وتسجيل مدة العملية وفقد البيانات، لا مجرد نجاح Backup Job. **دليل قبول مستقبلًا:** تظهر نتائج ملف محمي وتسجيل دخول للتطبيق بعد الاستعادة مع actual RTO/RPO. **المرجع:** [AWS-restore](https://docs.aws.amazon.com/aws-backup/latest/devguide/restore-testing.html).
- **CG-1434** — **Backup Destruction Resistance**: تفويضان منفصلان لتعديل سياسة النسخ أو حذفها، حماية immutable/soft-delete حسب المنتج، واختبار فقد مفاتيح/خادم الإدارة دون فقد كل النسخ. **دليل قبول مستقبلًا:** حساب مدير CyberGuard وحده لا يستطيع حذف آخر نسخة محمية في الـVault. **المرجع:** [Azure-backup](https://learn.microsoft.com/en-us/azure/backup/security-overview).

### G09 — السحابة والخصوصية والسيادة

**قرار الدراسة:** المحرك المحلي هو الافتراضي؛ الخروج للنماذج السحابية يحتاج موافقة وتصنيف معلومات وتسجيل بيانات مرسلة، دون أسرار أو دليل خام إلا بموجب سياسة صريحة.

**صلته بالمتطلبات الموجودة:** CG-038–039، CG-046–051، CG-1027–1040.

- **CG-1435** — **Per-Field AI Egress Control**: سياسة تقييد cloud AI حسب tenant/data class/region/provider/purpose والحقول الحساسة؛ الوضع الافتراضي local/no external egress. **دليل قبول مستقبلًا:** سؤال عن بيانات AD سرية يبقى محليًا، وأي طلب Cloud يمر على بوابة سياسة مستقلة. **المرجع:** [OWASP-Agent](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html).
- **CG-1436** — **Cloud Connector Read-Only Boundaries**: حساب/اشتراك/مشروع بصلاحيات قراءة منفصلة وعُمر توكن محدد، وعدم السماح لطريق تحليل السحابة بالوصول إلى صلاحيات تنفيذ. **دليل قبول مستقبلًا:** تسريب توكن connector read-only لا يسمح بتعديل Security Groups أو حذف نسخ. **المرجع:** [NIST-ZT](https://csrc.nist.gov/pubs/sp/800/207/final).
- **CG-1437** — **Saudi Regulatory Applicability Record**: تحديد ما إذا كانت الجهة خاضعة لضوابط NCA ECC والقواعد ذات الصلة، وسياسة الاحتفاظ والنقل والتعاقد قبل اختيار منطقة استضافة أو مزود AI. **دليل قبول مستقبلًا:** يُظهر تقرير العميل Applicable/Not Assessed/Not Applicable مع مصدر وسبب، لا شهادة امتثال وهمية. **المرجع:** [NCA-ECC](https://nca.gov.sa/ar/regulatory-documents/controls-list/ecc/).

### G10 — جاهزية الإصدار وقابلية التشغيل

**قرار الدراسة:** لا تُحسب الميزة ضمن المنتج الجاهز إلا بوجود بيئة supported + سيناريو positive/negative + safety + performance + rollback + source evidence.

**صلته بالمتطلبات الموجودة:** CG-927–936، CG-1285–1300، CG-1410.

- **CG-1438** — **Requirement-to-Evidence Traceability**: كل خاصية لها IDs وربط Requirement → Implementation Owner → Connector → Test → Result → Build Version → Approval؛ فصل Verified/Unverified/Blocked. **دليل قبول مستقبلًا:** شاشة Feature Coverage لا تعد ميزة لم تجتز الاختبار على أنها جاهزة. **المرجع:** [NIST-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final).
- **CG-1439** — **Cross-Platform Security Acceptance Pack**: حزمة قبول لأنظمة Windows/macOS/Linux مع حالات RDP وagent/no-agent وremote session وAV active/passive وoffline وloss/tamper وrecovery. **دليل قبول مستقبلًا:** تنتج CI/Test run أدلة مؤرخة مستقلة عن ملخص AI لكل نظام مدعوم. **المرجع:** [OWASP-ASVS](https://asvs.owasp.org/).
- **CG-1440** — **Release Blockers and Known Limitations**: رفض الإعلان عن Complete إذا فشل مسار منع حساس أو تأخر تنبيه حرج أو لم تتوفر صلاحيات أو اجتاز إصدار غير مختبر؛ قوائم exclusions/unsupported واضحة. **دليل قبول مستقبلًا:** محاكاة إخفاق Restore تستدعي release blocker، ولا يمكن تغييرها إلى Passed دون evidence. **المرجع:** [NIST-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final).

## مواصفات تشغيل النسخة الأولى عند اعتمادها لاحقًا

### A. الحد الأدنى من الوظائف التي لا يجوز تزييفها
- يظهر الجهاز ببيانات مثبتة أو Unknown؛ لا يدّعي التعرف إلى نظام التشغيل اعتمادًا على MAC وحده.
- تُعرض «Port exposed» و«RDP connected» و«Active remote session» كحالات مختلفة؛ هوية A وB قد تكون Unknown خلف relay.
- أي مصدر سجلات مفقود يُظهر Visibility Gap ولا يغيّر عدد الأحداث إلى صفر آمن.
- إذا أوقف AV آخر منع التنفيذ، لا يدعي CyberGuard أن «حماية Real-time» مفعّلة دون اختبارات مناسبة.
- لا يطلب AI من تلقاء نفسه كلمة مرور مستخدم، ولا يملك shell حرًا، ولا يغير الشبكة مباشرة؛ إجراء port shutdown بواسطة NCC مع تحقق مسبق.
- كل استعادة Backup تُقاس باختبار وظيفي منفصل عن نجاح نقل البيانات.

### B. سياسة الاختبارات والتشغيل
| بوابة القبول | معيار القرار | الحالة اليوم |
|---|---|---|
| تكامل Windows/macOS/Linux | دليل OS/build/kernel + اختبار جرد/منع/سجلات/تعطل ضمن الدعم المعلن | لم يبدأ |
| إسناد Source A وTarget B | 2 طرف مستقل، حسابات مفصولة، إثبات جلسة، NAT/Relay دون نسب خاطئ | لم يبدأ |
| حماية عميل مؤسسي | إثبات تكامل EDR وعدم تعارض AV | لم يبدأ |
| محاكاة اختبار هجومي | اختبار مسموح محدود بشهادة تفويض ولغة تقرير دقيقة | لم يبدأ |
| الموافقات | نسخ إذن، إعادة تحقق، رفض scope/expiry mismatch | لم يبدأ |
| التنبيه الحرج | اختبار End-to-End، ACK حقيقي أو تصعيد، لا بيانات سرية عبر push | لم يبدأ |
| تعطل منصة التحكم | وقف الإجراءات، إنذار مستقل، عودة موثقة | لم يبدأ |
| التعافي | استعادة مستقلة وفحص عمل الخدمات، RTO/RPO فعليان | لم يبدأ |
| DevSecOps | SAST/SCA/SBOM/ASVS/توقيعات، إصلاح البلوكر قبل الإعلان | لم يبدأ |
| تراخيص وسيادة | موافقة قانونية/أمنية وتقييم البيانات حسب كل عميل | لم يبدأ |

### C. قرار استخدام الأدوات الموثقة لا اختراع تسويق
- **Security Prevention:** منتج EDR/AV مدعوم ومصرح به لكل بيئة؛ أولوية التوافق وحالة الـActive/Passive على مضاهاة محرك تجاري عملاق منذ أول إصدار.
- **OS telemetry:** Windows Events/Sysmon/Defender APIs، macOS Endpoint Security system extension مع entitlement، Linux eBPF/audit/syslog حسب النواة والتوزيعة؛ أي ميزة غير متاحة = Unavailable.
- **Network context:** Netdisco/LLDP/FDB/DHCP/AD/NAC APIs للأدلة، دون ادعاء أن الكمبيوتر يرى كل الهوستات أو حركة الشبكة.
- **AI investigator:** محلل مع grounded citations، محرّك أوامر مستقل؛ كل تجارب مهاجم مؤثرة تكون في مختبر مصرح مع stop conditions.
- **Recovery:** استخدام APIs لمزود النسخ، مع اختبار استعادة مستقل؛ لا تعني قراءة Snapshot أن النظام قابل للاستعادة.
- **Security for software:** NIST SSDF + OWASP ASVS + SBOM وسلسلة التحديثات الموقعة؛ اختبارات مستقلة في البناء.

### D. قرارات حرجة معلقة لا يجوز ادعاء حسمها
1. اختيار محرك الحماية أو المنتجات التجارية الحقيقية وترخيص كل عميل؛ لا تُعرف دون بيئة التشغيل.
2. نظام قاعدة البيانات والتخزين والتوزيع والـHA/SLO وفق تكلفة وحجم التليمتري وتقدير 20,000 أصل، تحتاج تجربة حمل.
3. دعم إصدارات Windows Server القديمة ومدى الامتثال؛ لا يوجد وعد بالحماية الكاملة للأنظمة المنتهية الدعم.
4. الحصول على صلاحيات Apple اللازمة، وKernel capability لنظم Linux، لا يمكن ضمانه مسبقًا لكل جهاز.
5. صلاحيات قراءة/إدارة Cisco/Huawei/AD والـcloud tenant بحسب تراخيص الموقع، وتحتاج موافقة المالك.
6. طبيعة عقد خدمات AI السحابية وموضع حفظ البيانات/إعادة استخدامها/المنطقة القانونية لكل مزود.
7. الأرقام المستهدفة للأداء والاحتفاظ والتكلفة والزمن؛ تُقترح بعد نموذج حجم موارد واختبار.
8. اعتماد سيناريوهات قبول مستقلة وعدم إعلان أن 1,440 متطلبًا كلها مطبقة/مختبرة.

### E. مصدر الحقيقة وتتبع التداخل المعنوي
- الرقم CG ثابت للرجوع التاريخي، لكن يجب فصل **متطلبات المنتج النشطة** عن المقترحات القديمة/التكرارات/المنقولة إلى NCC/Tickets/IT Twin.
- العدد التراكمي ليس عدد الميزات المنفذة. يلزم تصنيف كل واحدة: Active, Duplicate-Of, Moved-To, Research, Blocked, Verified.
- لم تجرِ مراجعة يدوية دلالية شاملة للمتطلبات الألف والأربعمائة؛ تم التحقق فقط من التسلسل، وتحتاج المهمة مراجعة منظمة قبل البرومبت الكبير.

## المصادر البحثية الرسمية
- [MDE-AV](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility)
- [Apple-ES](https://developer.apple.com/documentation/bundleresources/system-extensions)
- [Tetragon](https://tetragon.io/docs/installation/faq/)
- [OCSF](https://github.com/ocsf/ocsf-schema)
- [Netdisco](https://github.com/netdisco/netdisco)
- [MITRE-Caldera](https://www.mitre.org/our-impact/intellectual-property/caldera)
- [OWASP-Agent](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)
- [NIST-ZT](https://csrc.nist.gov/pubs/sp/800/207/final)
- [NIST-Identity](https://csrc.nist.gov/pubs/sp/800/63/B/4/final)
- [NIST-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final)
- [NIST-IR](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [NIST-BCP](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-34r1.pdf)
- [AWS-restore](https://docs.aws.amazon.com/aws-backup/latest/devguide/restore-testing.html)
- [Azure-backup](https://learn.microsoft.com/en-us/azure/backup/security-overview)
- [CISA-KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NCA-ECC](https://nca.gov.sa/ar/regulatory-documents/controls-list/ecc/)
- [OWASP-ASVS](https://asvs.owasp.org/)
- [CISA-SBOM](https://content.govdelivery.com/accounts/USDHSCISA/bulletins/422a7eb)
- [MITRE-Evals](https://attackevals.mitre.org/enterprise/er8)

**خلاصة الدراسة:** خطة الإغلاق جاهزة لمرحلة *صياغة البرومبت الهندسي/المواصفات*، لكنها ليست نتيجة اكتمال التنفيذ. لا تبدأ أداة اختبار أو نشر أو تعديل أي أصل دون تفويض لاحق.

## مراجعة التداخل المعنوي الأولية — لا نمحو المتطلبات التاريخية

هذا الفحص يُظهر أمثلة لمتطلبات متقاربة الغرض، دون الجزم بأنها متطابقة: 

| الإضافة الجديدة | المتطلب الموجود | القرار |
|---|---|---|
| CG-1415 | CG-1245 | تقييد إضافي: عدم تجاوز أذونات Apple؛ يُربط بالمتطلب الأصلي لا يُعرض كميزة ثانية |
| CG-1418 | CG-802 | تقييد إضافي: Provenance وعدم استنتاج منفذ جهاز نهائي خلف وسيط |
| CG-1419 | CG-1264 | تفصيل: إثبات الفجوات عند تعطيل مصادر الرؤية |
| CG-1425 | CG-1408 | تفصيل: التحقق بعد التنفيذ والتراجع؛ المتطلب القديم خاص بالجلسات |
| CG-1429 | CG-1270 | تفصيل: الاحتفاظ بأصل الحدث وربط النسخة/الـParser |
| CG-1431 | CG-1122 | تفصيل: الإثبات والتصعيد، وليس إشعارًا منفصلًا |
| CG-1433 | CG-859 / CG-1296 | توحيد معايير الاختبار المعزول وقياس RTO/RPO |
| CG-1434 | CG-860 | تشديد صلاحيات حذف النسخ وحماية مخزنها |

**مهم:** لم تُستكمل مراجعة دلالية يدوية لكل المتطلبات الـ1,440. وفحص التشابه اللفظي الآلي لا يكفي وحده لإعلان إزالة التكرار. يوضع للمتطلبات المشتركة لاحقًا `Refines` أو `Duplicate-Of` بعد مراجعة بشرية. بذلك يبقى التاريخ محفوظًا ولا نبالغ في عدد الميزات المستقلة.