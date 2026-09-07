# نشر «مكتبة القارئ» على Railway

هذه النسخة مجهزة للعمل على Railway مع قاعدة SQLite محفوظة على Volume دائم.

## الإعدادات المطلوبة في Railway

1. ارفع المشروع إلى مستودع GitHub خاص.
2. من Railway أنشئ مشروعًا جديدًا واختر Deploy from GitHub Repo.
3. اختر مستودع `maktabat-alqari`.
4. افتح خدمة الموقع ثم Variables وأضف:
   - `NODE_ENV=production`
   - `DB_PATH=/data/reader-library.db`
   - `SESSION_SECRET=` قيمة طويلة وعشوائية
   - `INITIAL_PASSWORD=` كلمة مرور قوية للحسابات الأولية
5. أضف Volume للخدمة واجعل Mount Path هو `/data`.
6. من Settings > Networking اختر Generate Domain.
7. افتح الرابط الذي ينشئه Railway.

## الحسابات الأولية

- مشارك: `odai`
- مشرف: `supervisor`
- مدير: `manager`
- كلمة المرور: القيمة التي وضعتها في `INITIAL_PASSWORD` عند أول تشغيل فقط.

> ملاحظة: إذا كانت قاعدة البيانات قد أُنشئت سابقًا، تغيير `INITIAL_PASSWORD` لاحقًا لا يغير كلمات مرور الحسابات الموجودة تلقائيًا.

## مهم جدًا

لا تنشر SQLite على Railway بدون Volume. يجب أن يكون المسار `/data` وأن يكون `DB_PATH=/data/reader-library.db` حتى تبقى البيانات بعد إعادة النشر.
