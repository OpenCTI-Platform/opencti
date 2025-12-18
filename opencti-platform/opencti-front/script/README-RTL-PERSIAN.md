# RTL و فارسی‌سازی OpenCTI Front

این اسکریپت برای اعمال پچ RTL (راست‌چین) و پشتیبانی از زبان فارسی در OpenCTI Front استفاده می‌شود.

## نحوه استفاده

### روش 1: با ترجمه خودکار (توصیه می‌شود)

1. دریافت API Key از DeepL:
   - به https://www.deepl.com/pro-api بروید
   - یک حساب کاربری رایگان ایجاد کنید
   - API Key خود را دریافت کنید

2. تنظیم متغیر محیطی:
```bash
# Linux/Mac
export SUBSCRIPTION_KEY=your_deepl_api_key

# Windows PowerShell
$env:SUBSCRIPTION_KEY="your_deepl_api_key"

# Windows CMD
set SUBSCRIPTION_KEY=your_deepl_api_key
```

3. اجرای اسکریپت:
```bash
node script/apply-rtl-persian-patch.js
```
   - اسکریپت به صورت خودکار فایل‌های فارسی را ترجمه می‌کند

4. نصب وابستگی‌های جدید:
```bash
yarn install
```

5. تست برنامه:
   - زبان را در تنظیمات به "فارسی" تغییر دهید
   - رابط کاربری باید راست‌چین شود

### روش 2: بدون ترجمه خودکار

1. اجرای اسکریپت:
```bash
node script/apply-rtl-persian-patch.js
```

2. نصب وابستگی‌های جدید:
```bash
yarn install
```

3. ترجمه فایل‌های فارسی:
   - فایل‌های `lang/front/fa.json` و `lang/back/fa.json` را به صورت دستی ترجمه کنید
   - یا بعداً با تنظیم `SUBSCRIPTION_KEY` و اجرای مجدد اسکریپت، ترجمه خودکار انجام دهید
   - یا از اسکریپت موجود استفاده کنید:
     ```bash
     export SUBSCRIPTION_KEY=your_key
     node script/auto-translate.js
     ```

4. تست برنامه:
   - زبان را در تنظیمات به "فارسی" تغییر دهید
   - رابط کاربری باید راست‌چین شود

## تغییرات اعمال شده

1. **AppThemeProvider.tsx**: 
   - اضافه شدن پشتیبانی از RTL با استفاده از `stylis-plugin-rtl`
   - اضافه شدن `CacheProvider` برای RTL
   - تشخیص خودکار جهت بر اساس زبان کاربر

2. **AppIntlProvider.tsx**:
   - اضافه شدن زبان فارسی (`fa-ir`) به لیست زبان‌های موجود
   - اضافه شدن `faIR` از `date-fns/locale`
   - اضافه شدن فایل‌های ترجمه فارسی

3. **useDocumentModifier.ts**:
   - اضافه شدن `useDocumentDirectionModifier` برای تغییر جهت صفحه

4. **تبدیل CSS Properties به RTL-safe**:
   - تبدیل `marginLeft`/`marginRight` به `marginInlineStart`/`marginInlineEnd`
   - تبدیل `paddingLeft`/`paddingRight` به `paddingInlineStart`/`paddingInlineEnd`
   - تبدیل `borderTopLeftRadius`/`borderTopRightRadius` به `borderStartStartRadius`/`borderStartEndRadius`
   - تبدیل `float: left/right` به `float: inline-start/inline-end`
   - تبدیل `textAlign: left/right` به `textAlign: start/end`
   - تبدیل معادل‌های CSS (kebab-case) نیز انجام می‌شود
   - این تبدیل‌ها به صورت خودکار در تمام فایل‌های `.tsx`, `.jsx` و `.css` انجام می‌شود
   - **Idempotent**: اگر فایلی قبلاً تبدیل شده باشد، دوباره تبدیل نمی‌شود
   - **Incremental**: فایل‌های جدید که اضافه می‌شوند، در اجراهای بعدی بررسی و تبدیل می‌شوند

5. **package.json**:
   - اضافه شدن `stylis-plugin-rtl` به dependencies

6. **فایل‌های ترجمه**:
   - ایجاد `lang/front/fa.json` و `lang/back/fa.json`

## نکات مهم

- این اسکریپت تغییرات را به صورت مستقیم روی فایل‌های اصلی اعمال می‌کند
- قبل از اجرا، حتماً از کد خود بکاپ بگیرید
- اگر `SUBSCRIPTION_KEY` تنظیم شده باشد، اسکریپت به صورت خودکار فایل‌های فارسی را ترجمه می‌کند
- ترجمه خودکار ممکن است چند دقیقه طول بکشد (بسته به حجم فایل‌ها)
- پس از ترجمه خودکار، بهتر است ترجمه‌ها را بررسی و در صورت نیاز اصلاح کنید
- اگر ترجمه خودکار انجام نشد، می‌توانید فایل‌ها را به صورت دستی ترجمه کنید

### درباره تبدیل CSS Properties

- اسکریپت به صورت خودکار تمام فایل‌های `.tsx`, `.jsx` و `.css` را بررسی می‌کند
- فقط فایل‌هایی که نیاز به تبدیل دارند، تبدیل می‌شوند
- اگر فایلی قبلاً تبدیل شده باشد (دارای `marginInlineStart` و غیره)، دوباره تبدیل نمی‌شود
- **می‌توانید اسکریپت را چندین بار اجرا کنید**: فایل‌های جدید که بعداً اضافه می‌شوند، در اجراهای بعدی بررسی و تبدیل می‌شوند
- تبدیل‌ها شامل:
  - Margin و Padding (left/right → inline-start/inline-end)
  - Border radius (top-left/top-right → start-start/start-end)
  - Float و Text-align (left/right → inline-start/inline-end یا start/end)

