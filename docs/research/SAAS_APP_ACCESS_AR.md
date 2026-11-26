# بحث CG-159: وصول التطبيقات الخارجية وShadow IT في SaaS

تاريخ المراجعة: 2026-11-27. المصادر رسمية من Microsoft وGoogle، والروابط في آخر الوثيقة.

## السؤال

كيف نعرف أي التطبيقات الخارجية تصل إلى بيانات المؤسسة في Microsoft 365 وGoogle Workspace، وبأي صلاحيات، ومن سمح لها؟ وكيف نفعل ذلك دون فحص محتوى الموظفين؟

## Microsoft Entra

### سياسة موافقة المستخدم

- **مكان الإعداد:** خاصية `permissionGrantPoliciesAssigned` داخل `defaultUserRolePermissions` في `authorizationPolicy`.
- **القيم المهمة:**

| القيمة | المعنى |
|---|---|
| لا توجد قيمة تبدأ بـ `ManagePermissionGrantsForSelf.` | موافقة المستخدم **معطلة**. سياسات `ManagePermissionGrantsForOwnedResource.*` وحدها لا تسمح بها. |
| `ManagePermissionGrantsForSelf.microsoft-user-default-low` | موافقة محدودة: تطبيقات الناشرين الموثقين والتطبيقات المسجلة في المستأجر، وللصلاحيات المصنفة «منخفضة الأثر» فقط. |
| `ManagePermissionGrantsForSelf.microsoft-user-default-legacy` | يستطيع أي مستخدم الموافقة لأي تطبيق على أي صلاحية لا تتطلب موافقة مسؤول. |

- **توصية Microsoft:** السماح بموافقة المستخدم لتطبيقات الناشرين الموثقين فقط.
- **أثر التغيير:** تغيير السياسة يؤثر على الموافقات القادمة فقط، أما الموافقات الموجودة فتبقى. لذلك يلزم جرد المنح الحالية.

### المنح الحالية

- **المصدر:** `oauth2PermissionGrant`.
- **`clientId`:** معرّف كائن التطبيق، وليس `appId`.
- **`consentType`:**
  - `AllPrincipals`: موافقة مسؤول تخوّل التطبيق انتحال كل المستخدمين.
  - `Principal`: موافقة مستخدم واحد، ومعرّفه في `principalId`.
- **`scope`:** قائمة صلاحيات مفصولة بمسافات.

### المشاركة الخارجية في SharePoint وOneDrive

- **المستويات:**
  - **Anyone:** روابط بلا مصادقة.
  - **New and existing guests:** ضيوف جدد وحاليون.
  - **Existing guests:** الضيوف الحاليون فقط.
  - **Only people in your organization:** المشاركة الخارجية مغلقة.
- إعداد OneDrive يمكن أن يكون أشد من إعداد SharePoint، ولا يمكن أن يكون أوسع منه.
- يمكن فرض انتهاء على روابط Anyone بعدد أيام.

## Google Workspace

- **المصدر:** `tokens.list` في Directory API.
  - يعيد لكل مستخدم الرموز الممنوحة: `clientId` و`displayText` و`scopes`.
  - و`anonymous` تعني أن معرّف العميل مجهول، و`nativeApp` تعني تطبيقًا مثبتًا.
- **إعداد وصول كل تطبيق:** من API controls، وقيمه Trusted وLimited وSpecific Google data وBlocked.
- **إعداد التطبيقات غير المُعدة:**
  - السماح بأي تطبيق.
  - السماح فقط بالتطبيقات التي تطلب معلومات «تسجيل الدخول بحساب Google» الأساسية.
  - المنع.
- تنشر Google قائمة نطاقات «عالية الخطورة» لكل من Gmail وDrive وChat، منها `https://mail.google.com/` و`gmail.send` و`drive` و`drive.readonly`.
- **مشاركة Drive:**
  - صلاحية الملف من نوع `anyone` أو `domain`.
  - `allowFileDiscovery` تعني أن الملف قابل للبحث.

## القرار في CyberGuard

1. **يجرد التطبيقات ولا يفتح المحتوى:** يُحفظ لكل تطبيق:
   - الاسم.
   - المعرّف.
   - الناشر الموثق أو المراجعة الإدارية.
   - النطاقات.
   - عدد المستخدمين.
   - موافقة المسؤول.

   ولا تُحفظ معرّفات المستخدمين، بل عددهم فقط.
2. **مشاركة الملفات بعدّ فقط وبشرط:** لا تُعد إلا بمرجع سياسة خصوصية للموظفين (`--privacy-policy-ref`).
   - لا تُقرأ أسماء الملفات.
   - النطاقات الخارجية تُحسب عددًا فقط.
   - يرفض المدقق في الخادم أي تعرّض للملفات دون هذا المرجع.
3. **لا محتوى أبدًا:** يرفض السكربت خيارات البريد والملفات والمحادثات، ولا يطلب أي نطاق محتوى.
4. **التنبيه `CG-SAAS-APP-ACCESS-159`:** يُطلق في الحالات التالية:
   - سياسة موافقة مفتوحة لأي تطبيق.
   - تطبيق غير موثق أو غير مُراجع يملك نطاقات بريد أو ملفات أو دليل.
   - تطبيق محظور ما زال يملك رموزًا.
   - عميل مجهول.
   - روابط Anyone دون انتهاء.
   - ملفات عامة قابلة للبحث.
5. **حالة Google:** لا تعلن Google «ناشرًا موثقًا» في `tokens.list`، لذلك يعتمد التقييم هناك على إعداد وصول التطبيق في API controls.

## الحدود

- قائمة نطاقات Google عالية الخطورة في الكود جزء من القائمة المنشورة، والمرجع الكامل صفحة Google.
- تصنيف Entra للنطاقات الخطرة يعيد استخدام النمط المستخدم في موافقات OAuth في CG-012.
- لم يُجرَّب على مستأجر حقيقي، بل على تصديرات اصطناعية.

## المصادر

- https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent
- https://learn.microsoft.com/en-us/graph/api/resources/oauth2permissiongrant
- https://learn.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off
- https://developers.google.com/workspace/admin/directory/reference/rest/v1/tokens
- https://support.google.com/a/answer/7281227
- https://developers.google.com/workspace/drive/api/reference/rest/v3/permissions
