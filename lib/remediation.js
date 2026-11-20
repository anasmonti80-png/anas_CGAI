// CG-067 Best way to fix each issue for its environment and asset type, with limitations and uncertainty stated.
// Deterministic: the issue family comes from the alert rule; options (fix the root cause, mitigate, compensate, contain)
// are adjusted to the asset type, operating system, vendor support, service criticality, maintenance windows and the
// rollout stage. Options that do not apply say why. Unknown facts lower the confidence and are listed, never guessed.
// Advice only: any device change still goes through the typed response workflow with approval.
const P = (en, ar) => ({ en, ar });
export const families = {
  vulnerability: { match: r => /^CG-VULN-|^CG-REPORTED-FINDING/.test(r), title: P('Exploitable or reported vulnerability', 'ثغرة قابلة للاستغلال أو مبلغ عنها'),
    root: P('Install the vendor security update for the affected product, then confirm the version in the next software inventory.', 'ثبّت تحديث المورد الأمني للمنتج المتأثر، ثم تأكد من الإصدار في جرد البرمجيات التالي.'),
    mitigate: P('Apply the vendor workaround: disable the vulnerable feature or service, or restrict who can reach it.', 'طبّق حل المورد المؤقت: عطّل الميزة أو الخدمة الضعيفة أو قيّد من يصل إليها.'),
    compensate: P('Limit network reach to the asset (allow-list sources, block the service port at the edge) and increase monitoring until it is fixed.', 'قلّل الوصول الشبكي للأصل (قائمة سماح للمصادر وحظر منفذ الخدمة على الحافة) وزد المراقبة حتى الإصلاح.'),
    action: 'network.block-port', verify: P('The vulnerability no longer matches the next software inventory and the alert resolves.', 'لا تطابق الثغرة جرد البرمجيات التالي ويُغلق التنبيه.') },
  exposure: { match: r => /^CG-(FW-EXPOSE|NET-EXPOSE|REMOTE-EXPOSURE|WAF|EASM|NETPOSTURE|NAC-POLICY)-?/.test(r), title: P('Service exposed more widely than needed', 'خدمة مكشوفة أكثر من اللازم'),
    root: P('Remove or narrow the rule that exposes the service; publish it only through an authenticated gateway or VPN.', 'احذف القاعدة التي تكشف الخدمة أو ضيّقها؛ وانشرها فقط عبر بوابة موثقة أو VPN.'),
    mitigate: P('Restrict the source addresses allowed to reach the service.', 'قيّد عناوين المصادر المسموح لها بالوصول إلى الخدمة.'),
    compensate: P('Require MFA on the exposed service and alert on every connection from outside the allowed sources.', 'اشترط MFA على الخدمة المكشوفة ونبّه على كل اتصال من خارج المصادر المسموحة.'),
    action: 'network.block-port', verify: P('The next firewall or configuration export no longer shows the exposure.', 'لا يظهر الكشف في تصدير الجدار الناري أو الإعدادات التالي.') },
  endpoint: { match: r => /^CG-(MAL|RAN|TAMPER|AGENT-NOAV|PROTECTION-NOT-RUNNING|FILE|LINUX-PERSIST)/.test(r), title: P('Malicious activity or missing protection on an endpoint', 'نشاط خبيث أو حماية غائبة على جهاز'),
    root: P('Remove the malicious artefact or persistence, restore the protection agent and its policy, and reset credentials used on the host.', 'أزل الأثر الخبيث أو آلية الاستمرارية، وأعد وكيل الحماية وسياسته، وأعد تعيين بيانات الاعتماد المستخدمة على الجهاز.'),
    mitigate: P('Block the offending application or file hash and stop the related service.', 'احظر التطبيق أو بصمة الملف المسببة وأوقف الخدمة المرتبطة.'),
    compensate: P('If the host cannot be cleaned now, restrict its network access to management only.', 'إذا تعذر تنظيف الجهاز الآن فقيّد وصوله الشبكي إلى الإدارة فقط.'),
    action: 'endpoint.isolate-device', verify: P('Protection reports running and no new detections from the host for 24 hours.', 'تبلغ الحماية أنها تعمل ولا اكتشافات جديدة من الجهاز لمدة 24 ساعة.') },
  identity: { match: r => /^CG-(IDENT|AUTH-FAILURES|ACCESS-FAIL|LINUX-SUDO|MGMT-ACCESS)/.test(r), title: P('Identity misuse or suspicious sign-in', 'إساءة استخدام هوية أو دخول مريب'),
    root: P('Reset the affected credentials, revoke active sessions and tokens, and review the change or grant that triggered the alert.', 'أعد تعيين بيانات الاعتماد المتأثرة، وألغِ الجلسات والرموز النشطة، وراجع التغيير أو الصلاحية التي سببت التنبيه.'),
    mitigate: P('Enforce phishing-resistant MFA and conditional access for the account.', 'افرض MFA مقاومًا للتصيد ووصولًا مشروطًا للحساب.'),
    compensate: P('Block the source addresses of the attempts and lower the account privileges until reviewed.', 'احظر عناوين مصادر المحاولات وخفّض صلاحيات الحساب حتى المراجعة.'),
    action: 'network.block-ip', verify: P('No new failed or anomalous sign-ins for the account and the directory audit shows the reverted change.', 'لا محاولات دخول فاشلة أو غير طبيعية جديدة للحساب ويظهر تدقيق الدليل التغيير المسترجع.') },
  network: { match: r => /^CG-(NET-LATERAL|NET-DNS|LOG-IDS|REMOTE-SUSPICIOUS|NETCORR)/.test(r), title: P('Suspicious network activity', 'نشاط شبكي مريب'),
    root: P('Identify the process and account behind the traffic on the source host and remove it; close the path between segments that should not talk.', 'حدد العملية والحساب وراء الحركة على جهاز المصدر وأزلها؛ وأغلق المسار بين الأجزاء التي لا يجب أن تتواصل.'),
    mitigate: P('Block the destination address or domain.', 'احظر عنوان أو نطاق الوجهة.'),
    compensate: P('Add segmentation rules and monitor the remaining allowed paths.', 'أضف قواعد تقسيم وراقب المسارات المسموحة المتبقية.'),
    action: 'dns.block-domain', verify: P('The flows or DNS lookups stop in the next log window.', 'تتوقف التدفقات أو استعلامات DNS في نافذة السجلات التالية.') },
  cloud: { match: r => /^CG-(CLOUD|AZURE)/.test(r), title: P('Cloud posture or activity finding', 'ملاحظة على وضع السحابة أو نشاطها'),
    root: P('Fix the resource or permission in the provider (preferably in infrastructure-as-code so it does not drift back) and resolve the provider finding.', 'أصلح المورد أو الصلاحية لدى المزود (ويفضل في البنية ككود حتى لا يعود) وأغلق ملاحظة المزود.'),
    mitigate: P('Restrict the permission or network rule to the minimum while the fix is prepared.', 'قيّد الصلاحية أو قاعدة الشبكة إلى الحد الأدنى أثناء تجهيز الإصلاح.'),
    compensate: P('Enable the provider logging for the region or service and alert on use of the risky permission.', 'فعّل سجلات المزود للمنطقة أو الخدمة ونبّه على استخدام الصلاحية الخطرة.'),
    action: null, verify: P('The next read-only cloud collection shows the corrected state.', 'يظهر الوضع المصحح في الجمع السحابي التالي للقراءة فقط.') },
  visibility: { match: r => /^CG-(LOST-COVERAGE|AGENT-LOST|LOG-DELIVERY-FAILED|VISIBILITY-GAP|DELIVERY-BACKLOG|NET-HEALTH|ASSET-UNREACHABLE)/.test(r), title: P('Lost visibility or delivery', 'فقدان رؤية أو توصيل'),
    root: P('Restore the collector, agent or log forwarding: check the service, its credential and the network path to CyberGuard.', 'أعد المجمع أو الوكيل أو تمرير السجلات: افحص الخدمة وبيانات اعتمادها ومسار الشبكة إلى CyberGuard.'),
    mitigate: P('Use the store-and-forward sender so data waits locally during outages.', 'استخدم المرسل ذا الطابور المحلي حتى تنتظر البيانات محليًا أثناء الانقطاع.'),
    compensate: P('Treat the affected assets as unmonitored in reports until receipt resumes.', 'اعتبر الأصول المتأثرة غير مراقبة في التقارير حتى يعود الاستلام.'),
    action: null, verify: P('The source returns to receiving and the backlog drains.', 'يعود المصدر إلى الاستلام ويُفرغ الطابور.') },
};
const generic = { title: P('Finding that needs analyst review', 'ملاحظة تحتاج مراجعة محلل'), root: P('Review the evidence, confirm the cause with the asset owner and fix it at the source.', 'راجع الأدلة وأكد السبب مع مالك الأصل وأصلحه من مصدره.'), mitigate: P('Reduce exposure of the affected asset while the cause is confirmed.', 'قلّل كشف الأصل المتأثر حتى يتأكد السبب.'), compensate: P('Increase monitoring of the asset.', 'زد مراقبة الأصل.'), action: null, verify: P('The alert does not recur after the fix.', 'لا يتكرر التنبيه بعد الإصلاح.') };
const kindOf = asset => { const t = `${asset?.device_type || ''} ${asset?.os_family || ''}`.toLowerCase(); return /firewall|switch|router|network|wlc|ap\b/.test(t) ? 'network-device' : /server/.test(t) ? 'server' : /workstation|laptop|desktop|windows|macos|linux/.test(t) ? 'endpoint' : /cloud|aws|azure|gcp/.test(t) ? 'cloud' : 'unknown'; };

export function remediationAdvice({ alert, asset, context = {}, lifecycle = {}, compatibility = null, rolloutStage = null, evidenceAgeDays = null }) {
  const famId = Object.keys(families).find(k => families[k].match(alert.rule_id)) || (alert.rule_id.startsWith('CG-HYP-') ? 'hypothesis' : 'generic'), fam = families[famId] || generic;
  const type = kindOf(asset), support = lifecycle?.vendor_support?.status || compatibility?.support_state || 'unknown', critical = context.service_criticality === 'critical' || context.service_criticality === 'high';
  const windows = Array.isArray(context.maintenance_windows) ? context.maintenance_windows : [], unsupported = ['ended', 'end-of-support'].includes(support);
  const notes = [], unknowns = [];
  if (type === 'unknown') unknowns.push(P('Asset type is not known', 'نوع الأصل غير معروف'));
  if (!asset?.os_family) unknowns.push(P('Operating system is not known', 'نظام التشغيل غير معروف'));
  if (support === 'unknown') unknowns.push(P('Vendor support status is not known', 'حالة دعم المورد غير معروفة'));
  if (!context.service_criticality) unknowns.push(P('Service criticality is not recorded', 'حرجية الخدمة غير مسجلة'));
  if (!context.owner) unknowns.push(P('Asset owner is not recorded', 'مالك الأصل غير مسجل'));
  if (evidenceAgeDays === null) unknowns.push(P('No evidence age available', 'عمر الأدلة غير متاح')); else if (evidenceAgeDays > 7) unknowns.push(P(`Evidence is ${Math.round(evidenceAgeDays)} days old; the state may have changed`, `عمر الأدلة ${Math.round(evidenceAgeDays)} يومًا؛ وقد تكون الحالة تغيرت`));
  const options = [
    { id: 'fix-root-cause', approach: 'fix-root-cause', ...fam.root, applies: !(famId === 'vulnerability' && unsupported), reason_not_applicable: famId === 'vulnerability' && unsupported ? P('The vendor no longer ships security updates for this product; upgrade or replace it.', 'المورد لم يعد يصدر تحديثات أمنية لهذا المنتج؛ رقّه أو استبدله.') : null },
    ...(famId === 'vulnerability' && unsupported ? [{ id: 'upgrade-or-replace', approach: 'fix-root-cause', ...P('Upgrade to a supported version or replace the asset; until then keep the compensating controls in place.', 'رقِّ إلى إصدار مدعوم أو استبدل الأصل؛ وحتى ذلك أبقِ الضوابط البديلة.'), applies: true, reason_not_applicable: null }] : []),
    { id: 'mitigate', approach: 'mitigate', ...fam.mitigate, applies: true, reason_not_applicable: null },
    { id: 'compensate', approach: 'compensate', ...fam.compensate, applies: true, reason_not_applicable: null },
    ...(fam.action ? [{ id: 'contain', approach: 'contain', ...P(`Request the typed response action ${fam.action} through the approval workflow if the risk is active now.`, `اطلب إجراء الاستجابة المحدد ${fam.action} عبر مسار الموافقة إذا كان الخطر نشطًا الآن.`), applies: !(critical && fam.action === 'endpoint.isolate-device'), reason_not_applicable: critical && fam.action === 'endpoint.isolate-device' ? P('Isolating a critical production asset stops its service; contain at the network edge instead.', 'عزل أصل إنتاجي حرج يوقف خدمته؛ احتوِ على حافة الشبكة بدلًا من ذلك.') : null, response_action: fam.action }] : [])];
  // Environment adjustments.
  if (type === 'network-device') notes.push(P('Network device: apply vendor firmware or configuration changes from the management plane, back up the configuration first and keep console access for rollback.', 'جهاز شبكة: طبّق البرنامج الثابت أو تغييرات الإعدادات من مستوى الإدارة، وخذ نسخة من الإعدادات أولًا، وأبقِ الوصول عبر المنفذ التسلسلي للتراجع.'));
  if (type === 'server') notes.push(P('Server: test the change on a staging copy and confirm dependent services before production.', 'خادم: اختبر التغيير على نسخة تجريبية وتأكد من الخدمات المعتمدة قبل الإنتاج.'));
  if (type === 'endpoint') notes.push(P('Endpoint: the change can usually be deployed through endpoint management outside working hours.', 'جهاز مستخدم: يمكن عادة نشر التغيير عبر إدارة الأجهزة خارج ساعات العمل.'));
  if (critical) notes.push(windows.length ? P(`Critical service: schedule in the recorded maintenance window (${windows.length} defined) with a tested rollback.`, `خدمة حرجة: جدول التغيير في نافذة الصيانة المسجلة (${windows.length}) مع تراجع مُختبر.`) : P('Critical service with no recorded maintenance window: agree a window with the owner before changing it.', 'خدمة حرجة بلا نافذة صيانة مسجلة: اتفق على نافذة مع المالك قبل التغيير.'));
  if (unsupported) notes.push(P('Vendor support has ended: fixes may not exist; plan replacement and keep compensating controls.', 'انتهى دعم المورد: قد لا توجد إصلاحات؛ خطط للاستبدال وأبقِ الضوابط البديلة.'));
  if (compatibility?.profile && compatibility.profile !== 'other') notes.push(P(`Legacy profile ${compatibility.profile}: agents or updates may not be available; prefer network-level controls.`, `ملف قديم ${compatibility.profile}: قد لا تتوفر الوكلاء أو التحديثات؛ فضّل الضوابط على مستوى الشبكة.`));
  if (rolloutStage && rolloutStage !== 'expansion') notes.push(P(`Rollout stage ${rolloutStage}: response actions are limited to the stage scope.`, `مرحلة التشغيل ${rolloutStage}: إجراءات الاستجابة محصورة في نطاق المرحلة.`));
  const confidence = unknowns.length === 0 ? 'high' : unknowns.length <= 2 ? 'medium' : 'low';
  return { alert_id: alert.id, rule_id: alert.rule_id, family: famId, family_title: fam.title, asset_type: type, vendor_support: support, critical_service: critical, recommended: options.find(o => o.applies)?.id || null, options, environment_notes: notes, verification: fam.verify,
    uncertainty: { confidence, unknowns }, limitations: [P('Advice is deterministic from the rule family and recorded asset facts; it is not a vendor-specific procedure.', 'النصيحة حتمية من عائلة القاعدة وحقائق الأصل المسجلة؛ وليست إجراء خاصًا بمورد معين.'), P('No change is made: device actions still need a typed request, approval and verification.', 'لا يُجرى أي تغيير: إجراءات الأجهزة تحتاج طلبًا محددًا وموافقة وتحققًا.')] };
}
