export interface SimulationScenario {
  id: string;
  code: string;
  titleEn: string;
  titleAr: string;
  categoryEn: string;
  categoryAr: string;
  briefEn: string;
  briefAr: string;
  evidenceLinesEn: string[];
  evidenceLinesAr: string[];
  threatOptions: Array<{ id: string; labelEn: string; labelAr: string }>;
  correctThreatId: string;
  actionOptions: Array<{ id: string; labelEn: string; labelAr: string }>;
  correctActionIds: string[];
  explanationEn: string;
  explanationAr: string;
  workflowEn: string[];
  workflowAr: string[];
}

export const SIMULATION_SCENARIOS: SimulationScenario[] = [
  {
    id: 'SIM-A',
    code: 'Scenario A',
    titleEn: 'Credential Phishing — Fake SSO Login Portal',
    titleAr: 'تصيد بيانات الاعتماد — بوابة تسجيل دخول مزيفة',
    categoryEn: 'Credential Phishing',
    categoryAr: 'سرقة بيانات الدخول',
    briefEn:
      'Multiple finance employees received an urgent email warning that their corporate mailbox will be locked in 2 hours unless they re-authenticate.',
    briefAr:
      'تلقى عدة موظفين في قسم المالية بريداً عاجلاً يحذر من إغلاق صناديق البريد خلال ساعتين ما لم يعيدوا المصادقة فوراً.',
    evidenceLinesEn: [
      'From: "IT Identity Desk" <alerts@micros0ft-sso-reset.top>',
      'Authentication-Results: spf=fail; dkim=fail; dmarc=fail',
      'Embedded Link: https://micros0ft-sso-reset.top/login?next=https://capture.top',
      'Proxy log confirms 1 user clicked the link 6 minutes ago.',
    ],
    evidenceLinesAr: [
      'المرسل: "IT Identity Desk" <alerts@micros0ft-sso-reset.top>',
      'نتائج المصادقة: spf=fail; dkim=fail; dmarc=fail',
      'الرابط المدمج: https://micros0ft-sso-reset.top/login?next=https://capture.top',
      'سجل البروكسي يؤكد نقر موظف واحد على الرابط قبل 6 دقائق.',
    ],
    threatOptions: [
      { id: 'cred_phish', labelEn: 'Credential Harvesting via Lookalike OAuth/SSO Domain', labelAr: 'سرقة بيانات الاعتماد عبر نطاق منتحل' },
      { id: 'benign_it', labelEn: 'Legitimate IT Maintenance Notice', labelAr: 'إشعار صيانة تقنية سليم' },
      { id: 'ransomware', labelEn: 'Local Disk Ransomware Encryption', labelAr: 'تشفير فدية محلي للأقراص' },
    ],
    correctThreatId: 'cred_phish',
    actionOptions: [
      { id: 'quarantine', labelEn: 'Quarantine email across all mailboxes', labelAr: 'عزل البريد من جميع الصناديق' },
      { id: 'block_domain', labelEn: 'Block lookalike domain at DNS / SWG proxy', labelAr: 'حظر النطاق المنتحل في DNS والبروكسي' },
      { id: 'reset_creds', labelEn: 'Revoke sessions & reset credentials for the user who clicked', labelAr: 'إبطال جلسات المستخدم الذي نقر وتغيير كلمة مروره' },
      { id: 'ignore_spf', labelEn: 'Whitelist sender domain immediately', labelAr: 'إضافة نطاق المرسل للقائمة البيضاء فوراً' },
    ],
    correctActionIds: ['quarantine', 'block_domain', 'reset_creds'],
    explanationEn:
      'The lookalike domain (micros0ft-sso-reset.top), urgency pressure, and failed SPF/DKIM/DMARC point clearly to credential harvesting. Because 1 user clicked, session revocation is mandatory alongside email quarantine and domain blocking.',
    explanationAr:
      'النطاق المنتحل (micros0ft-sso-reset.top) وضغط الاستعجال وفشل المصادقة تؤكد هجوم سرقة اعتماد. وبما أن مستخدماً واحداً نقر على الرابط، يجب إبطال جلساته مع عزل البريد وحظر النطاق.',
    workflowEn: [
      'Detection: Correlate email telemetry with proxy click logs.',
      'Containment: Quarantine email tenant-wide and block micros0ft-sso-reset.top.',
      'Eradication: Revoke active OAuth/SSO tokens and enforce MFA reset for exposed user.',
      'Recovery & Review: Monitor sign-in logs for 48 hours and update awareness training.',
    ],
    workflowAr: [
      'الاكتشاف: ربط بيانات البريد بسجلات البروكسي لتحديد المتأثرين.',
      'الاحتواء: عزل الرسالة وحظر النطاق المنتحل فوراً.',
      'الاستئصال: إبطال جلسات الدخول وإعادة تعيين كلمة المرور والمصادقة الثنائية.',
      'التعافي والمراجعة: مراقبة سجلات الدخول لمدة 48 ساعة وتحديث التوعية.',
    ],
  },
  {
    id: 'SIM-B',
    code: 'Scenario B',
    titleEn: 'Malicious Attachment — Disguised Double Extension',
    titleAr: 'مرفق خبيث — امتداد مزدوج مموّه',
    categoryEn: 'Malicious Attachment',
    categoryAr: 'مرفق تنفيذي خبيث',
    briefEn:
      'An accounts clerk forwarded a suspicious logistics invoice email containing an attachment named "Shipment_Receipt_882.pdf.exe".',
    briefAr:
      'أحال موظف حسابات بريداً مشبوهاً لفاتورة شحن يحتوي على مرفق باسم "Shipment_Receipt_882.pdf.exe".',
    evidenceLinesEn: [
      'From: "Courier Billing" <dispatch@dhl-express-clearance.click>',
      'Attachment: Shipment_Receipt_882.pdf.exe (1.8 MB)',
      'SHA-256 matches known loader IOC-105 in Threat Intelligence.',
      'Clerk reports downloading the file to Desktop but claims not running it.',
    ],
    evidenceLinesAr: [
      'المرسل: "Courier Billing" <dispatch@dhl-express-clearance.click>',
      'المرفق: Shipment_Receipt_882.pdf.exe (1.8 ميجابايت)',
      'تجزئة SHA-256 تطابق برمجية تحميل خبيثة معروفة IOC-105.',
      'أفاد الموظف بتنزيل الملف على سطح المكتب دون تشغيله حسب قوله.',
    ],
    threatOptions: [
      { id: 'malware_dropper', labelEn: 'Malware Loader Delivery via Double-Extension Executable', labelAr: 'توصيل برمجية خبيثة عبر ملف تنفيذي مزدوج الامتداد' },
      { id: 'bec_wire', labelEn: 'Executive Wire Fraud (BEC)', labelAr: 'احتيال مالي عبر انتحال مدير تنفيذي' },
      { id: 'false_positive', labelEn: 'Harmless Compressed PDF Invoice', labelAr: 'فاتورة PDF مضغوطة آمنة' },
    ],
    correctThreatId: 'malware_dropper',
    actionOptions: [
      { id: 'isolate_host', labelEn: 'Isolate endpoint workstation from network (Simulation)', labelAr: 'عزل محطة العمل عن الشبكة (محاكاة)' },
      { id: 'purge_email', labelEn: 'Quarantine email and block .exe/.scr attachments at gateway', labelAr: 'عزل البريد ومنع المرفقات التنفيذية عند البوابة' },
      { id: 'open_file', labelEn: 'Double-click the attachment on analyst laptop to check contents', labelAr: 'فتح المرفق على جهاز المحلل للتحقق منه' },
      { id: 'hash_sweep', labelEn: 'Sweep EDR for SHA-256 execution artifacts across endpoints', labelAr: 'فحص أجهزة الشبكة بحثاً عن مؤشرات تشغيل SHA-256' },
    ],
    correctActionIds: ['isolate_host', 'purge_email', 'hash_sweep'],
    explanationEn:
      'Never execute suspicious attachments on analyst machines. Because the payload reached disk, isolating the endpoint and sweeping EDR for the SHA-256 hash ensures no hidden execution occurred.',
    explanationAr:
      'يُحظر تماماً تشغيل المرفقات المريبة. وبما أن الملف وصل لجهاز الموظف، يجب عزل الجهاز وفحص الشبكة بحثاً عن تجزئة SHA-256 وعزل البريد عند البوابة.',
    workflowEn: [
      'Detection: Verify file hash against Threat Intelligence without executing.',
      'Containment: Isolate endpoint WS and quarantine all copies from mail server.',
      'Eradication: Remove payload from disk and run full EDR scan.',
      'Recovery: Re-enable network access only after clean EDR verification.',
    ],
    workflowAr: [
      'الاكتشاف: مطابقة بصمة الملف مع استخبارات التهديدات دون تشغيله.',
      'الاحتواء: عزل الجهاز وعزل جميع نسخ الرسالة من الخادم.',
      'الاستئصال: حذف الملف من القرص وإجراء فحص شامل.',
      'التعافي: إعادة اتصال الجهاز بعد التأكد التام من خلوه من البرمجيات الخبيثة.',
    ],
  },
  {
    id: 'SIM-C',
    code: 'Scenario C',
    titleEn: 'Business Email Compromise (BEC) — Urgent Wire Request',
    titleAr: 'اختراق البريد التجاري (BEC) — طلب تحويل مالي عاجل',
    categoryEn: 'Business Email Compromise',
    categoryAr: 'انتحال الصفة التنفيذية',
    briefEn:
      'Payroll received an email appearing to be from the CEO asking for an immediate confidential $48,000 vendor settlement while "in a board meeting".',
    briefAr:
      'تلقى قسم الرواتب بريداً يبدو من الرئيس التنفيذي يطلب تحويلاً سرياً فورياً بقيمة 48,000 دولار بحجة التواجد في اجتماع مجلس إدارة.',
    evidenceLinesEn: [
      'Display Name: "Tariq Al-Sayed (CEO)" <ceo.office.urgent@gmail.com>',
      'Reply-To: wire-approvals@yandex.com',
      'SPF=pass (for gmail.com) — valid Gmail infrastructure, spoofed persona.',
      'No malicious URLs or attachments; pure social engineering pressure.',
    ],
    evidenceLinesAr: [
      'الاسم الظاهر: "Tariq Al-Sayed (CEO)" <ceo.office.urgent@gmail.com>',
      'عنوان الرد: wire-approvals@yandex.com',
      'SPF=pass (لنطاق gmail.com) — خادم بريد سليم تقنياً لكن الهوية منتحلة.',
      'لا توجد روابط أو مرفقات خبيثة؛ هجوم هندسة اجتماعية بحت.',
    ],
    threatOptions: [
      { id: 'bec', labelEn: 'Business Email Compromise (Executive Impersonation Fraud)', labelAr: 'احتيال البريد التجاري عبر انتحال صفة الرئيس التنفيذي' },
      { id: 'ddos', labelEn: 'Distributed Denial of Service Attack', labelAr: 'هجوم حجب الخدمة الموزع' },
      { id: 'legit_ceo', labelEn: 'Authorized Executive Payment Request', labelAr: 'طلب دفع تنفيذي معتمد' },
    ],
    correctThreatId: 'bec',
    actionOptions: [
      { id: 'oob_verify', labelEn: 'Verify request out-of-band via known executive phone number', labelAr: 'التحقق عبر اتصال هاتفي مباشر بالرقم المعروف للمدير' },
      { id: 'hold_payment', labelEn: 'Place immediate hold on wire transfer & alert Finance', labelAr: 'إيقاف التحويل المالي فوراً وتنبيه الإدارة المالية' },
      { id: 'flag_sender', labelEn: 'Flag external free-mail impersonation & quarantine message', labelAr: 'وسم انتحال البريد المجاني وعزل الرسالة' },
      { id: 'reply_email', labelEn: 'Reply to wire-approvals@yandex.com asking for confirmation', labelAr: 'الرد على البريد المريب لطلب التأكيد' },
    ],
    correctActionIds: ['oob_verify', 'hold_payment', 'flag_sender'],
    explanationEn:
      'Notice SPF passed because the attacker actually sent from gmail.com! This demonstrates why authentication pass does not equal trust. Never reply to the attacker Reply-To address; always verify out-of-band.',
    explanationAr:
      'نجاح SPF هنا لأن المهاجم أرسل فعلاً من gmail.com، مما يثبت أن نجاح المصادقة لا يعني الموثوقية. يجب إيقاف الدفع والتحقق خارج نطاق البريد وعدم الرد على عنوان المهاجم.',
    workflowEn: [
      'Detection: Spot Display Name impersonation, free webmail, and Reply-To mismatch.',
      'Containment: Hold financial transaction and quarantine email.',
      'Eradication: Block external impersonation patterns via mail transport rules.',
      'Post-Incident: Enforce dual-authorization out-of-band policy for wire transfers.',
    ],
    workflowAr: [
      'الاكتشاف: رصد عدم تطابق الاسم الظاهر مع البريد المجاني واختلاف Reply-To.',
      'الاحتواء: تجميد التحويل المالي وعزل الرسالة.',
      'الاستئصال: إضافة قواعد حماية ضد انتحال أسماء التنفيذيين.',
      'ما بعد الحادث: فرض سياسة التحقق الثنائي خارج البريد للتحويلات المالية.',
    ],
  },
  {
    id: 'SIM-D',
    code: 'Scenario D',
    titleEn: 'Account Compromise — Post-Phishing Anomalous Login',
    titleAr: 'اختراق الحساب — تسجيل دخول شاذ بعد التصيد',
    categoryEn: 'Account Compromise',
    categoryAr: 'اختراق حساب مستخدم',
    briefEn:
      'Thirty minutes after a user clicked a suspicious link, identity telemetry shows logins from an unfamiliar ASN and new mailbox forwarding rules.',
    briefAr:
      'بعد 30 دقيقة من نقر مستخدم على رابط مريب، رصدت سجلات الهوية تسجيلاً من شبكة أجنبية وإنشاء قاعدة إعادة توجيه بريد.',
    evidenceLinesEn: [
      'Impossible travel: Riyadh (09:05) -> Unknown VPS ASN 185.220.101.47 (09:32).',
      'New Inbox Rule created: "Forward all emails containing invoice to ext-drop@proton.me".',
      'OAuth app "MailSync Pro" granted Read/Write Mail permissions.',
    ],
    evidenceLinesAr: [
      'سفر مستحيل: الرياض (09:05) ثم عنوان 185.220.101.47 (09:32).',
      'إنشاء قاعدة بريد جديدة لإعادة توجيه رسائل الفواتير إلى ext-drop@proton.me.',
      'منح صلاحيات قراءة وكتابة البريد لتطبيق OAuth مجهول "MailSync Pro".',
    ],
    threatOptions: [
      { id: 'ato', labelEn: 'Active Account Takeover (ATO) with Persistence Rules', labelAr: 'استيلاء نشط على الحساب مع قواعد استمرارية' },
      { id: 'vpn_travel', labelEn: 'Normal Corporate VPN Reconnect', labelAr: 'إعادة اتصال طبيعية بشبكة VPN المؤسسية' },
      { id: 'dns_cache', labelEn: 'Harmless DNS Cache Expiration', labelAr: 'انتهاء صلاحية ذاكرة DNS مؤقتة' },
    ],
    correctThreatId: 'ato',
    actionOptions: [
      { id: 'disable_acct', labelEn: 'Disable account / revoke all active refresh tokens (Simulation)', labelAr: 'تعطيل الحساب وإبطال كافة رموز الجلسة (محاكاة)' },
      { id: 'remove_rules', labelEn: 'Remove malicious inbox forwarding rule & rogue OAuth app', labelAr: 'حذف قاعدة إعادة التوجيه وتطبيق OAuth الخبيث' },
      { id: 'reset_mfa', labelEn: 'Reset password and re-register MFA hardware/authenticator', labelAr: 'تغيير كلمة المرور وإعادة تسجيل المصادقة الثنائية' },
      { id: 'leave_rule', labelEn: 'Leave forwarding rule active for 7 days to observe', labelAr: 'ترك قاعدة التحويل تعمل 7 أيام للمراقبة' },
    ],
    correctActionIds: ['disable_acct', 'remove_rules', 'reset_mfa'],
    explanationEn:
      'Resetting a password alone does not kill stolen OAuth tokens or remove hidden inbox forwarding rules! All three eradication steps are required to expel the attacker completely.',
    explanationAr:
      'تغيير كلمة المرور وحده لا يبطل رموز OAuth المسروقة ولا يحذف قواعد التوجيه الخفية؛ يجب تعطيل الجلسات وإزالة القاعدة والتطبيق وإعادة ضبط المصادقة الثنائية.',
    workflowEn: [
      'Containment: Disable compromised account and revoke all active sessions.',
      'Eradication: Delete external forwarding rule and revoke rogue OAuth grant.',
      'Recovery: Reset credentials, re-enroll MFA, and audit sent items for lateral phishing.',
    ],
    workflowAr: [
      'الاحتواء: تعطيل الحساب المخترق وإلغاء جميع الجلسات النشطة.',
      'الاستئصال: حذف قاعدة التوجيه وإلغاء صلاحيات تطبيق OAuth الخبيث.',
      'التعافي: إعادة تعيين كلمة المرور وMFA وفحص الرسائل الصادرة.',
    ],
  },
  {
    id: 'SIM-E',
    code: 'Scenario E',
    titleEn: 'Malicious URL — Deceptive Shortener & Redirect Chain',
    titleAr: 'رابط خبيث — اختصار روابط وسلسلة إعادة توجيه مضللة',
    categoryEn: 'Malicious URL',
    categoryAr: 'رابط تصيد مموّه',
    briefEn:
      'An employee received a shortened SMS/email link claiming to be a mandatory payroll portal update.',
    briefAr:
      'استلم موظف رابطاً مختصراً يدّعي أنه تحديث إلزامي لبوابة الرواتب.',
    evidenceLinesEn: [
      'Submitted URL: https://bit.ly/3xUpdateMfa',
      'Safe URL Inspection reveals open-redirect parameter and destination host paypa1-billing-security.xyz.',
      'Domain uses homoglyph numeral "1" replacing "l" and high-abuse .xyz TLD.',
    ],
    evidenceLinesAr: [
      'الرابط المقدم: https://bit.ly/3xUpdateMfa',
      'الفحص الآمن يكشف معاملة إعادة توجيه تقود إلى النطاق paypa1-billing-security.xyz.',
      'النطاق يستخدم الرقم "1" بدلاً من حرف "l" مع امتداد .xyz مرتفع المخاطر.',
    ],
    threatOptions: [
      { id: 'deceptive_url', labelEn: 'Obfuscated Phishing Redirect & Typosquatting URL', labelAr: 'إعادة توجيه تصيد مموهة ونطاق منتحل' },
      { id: 'internal_portal', labelEn: 'Verified Internal Payroll Portal', labelAr: 'بوابة رواتب داخلية موثوقة' },
      { id: 'sql_injection', labelEn: 'Database SQL Injection Exploit', labelAr: 'ثغرة حقن SQL في قاعدة البيانات' },
    ],
    correctThreatId: 'deceptive_url',
    actionOptions: [
      { id: 'inspect_sandbox', labelEn: 'Inspect via safe URL parser / sandbox (never click directly)', labelAr: 'فحص الرابط بمحلل آمن أو بيئة معزولة دون فتحه مباشرة' },
      { id: 'block_dest', labelEn: 'Block destination typosquat domain at web proxy & add IOC', labelAr: 'حظر النطاق المنتحل في البروكسي وإضافته لمؤشرات الاختراق' },
      { id: 'click_browser', labelEn: 'Open the bit.ly link in your personal browser to see where it goes', labelAr: 'فتح الرابط في المتصفح الشخصي لمعرفة وجهته' },
      { id: 'alert_staff', labelEn: 'Issue advisory warning staff against shortened payroll links', labelAr: 'توجيه تنبيه للموظفين ضد روابط الرواتب المختصرة' },
    ],
    correctActionIds: ['inspect_sandbox', 'block_dest', 'alert_staff'],
    explanationEn:
      'Attackers pair URL shorteners with typosquatted domains to bypass keyword filters. Analysts must never open unknown links directly on corporate or personal browsers.',
    explanationAr:
      'يجمع المهاجمون بين اختصار الروابط والنطاقات المنتحلة لتجاوز المرشحات. يُمنع فتح الروابط المريبة مباشرة ويجب فحصها بأدوات آمنة وحظر الوجهة النهائية.',
    workflowEn: [
      'Detection: Expand/parse URL safely without executing client browser navigation.',
      'Containment: Block final destination domain and log IOC.',
      'Recovery & Awareness: Notify target department and reinforce URL verification habits.',
    ],
    workflowAr: [
      'الاكتشاف: تحليل الرابط بأمان دون فتحه في المتصفح.',
      'الاحتواء: حظر النطاق النهائي وتوثيق مؤشر الاختراق.',
      'التعافي والتوعية: تنبيه الموظفين وتعزيز التحقق من الروابط.',
    ],
  },
];
