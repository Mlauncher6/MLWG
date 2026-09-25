<p align="center">
  <a href="README.md">🇬🇧 English</a>
  &nbsp;&nbsp;•&nbsp;&nbsp;
  <strong>🇮🇷 فارسی</strong>
</p>

<h1 align="center">MLUNCHER WORDPRESS GUARD</h1>

<p align="center">
  <strong>MLWG</strong> — سامانه متمرکز مدیریت، پایش و تحلیل امنیت WordPress
</p>

---

# معرفی

**MLUNCHER WORDPRESS GUARD (MLWG)** یک سامانه متمرکز برای **مدیریت، پایش و تحلیل امنیتی چندین سایت WordPress** است.

MLWG صرفاً یک افزونه ساده WordPress نیست و از دو بخش اصلی تشکیل شده است:

- **MLWG Manager** — پنل مدیریتی مرکزی نوشته‌شده با Python
- **MLWG Connector** — افزونه PHP نصب‌شده روی WordPress

ارتباط بین Manager و Connector از طریق فرآیندهای:

```text
Enrollment
Sync
Heartbeat
```

انجام می‌شود.

هدف این معماری، جمع‌آوری اطلاعات فنی و امنیتی WordPress و نمایش آن‌ها در یک Security Console مرکزی است.

---

# معماری

```text
                         ┌─────────────────────────┐
                         │       MLWG MANAGER       │
                         │                         │
                         │ Python 3.11+            │
                         │ SQLite                  │
                         │ Dashboard               │
                         │ Findings                │
                         │ Jobs                    │
                         │ Audit Log               │
                         └────────────┬────────────┘
                                      │
                              HMAC-SHA256
                              احراز هویت
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │     MLWG CONNECTOR      │
                         │                         │
                         │ PHP / WordPress        │
                         │ Enrollment              │
                         │ Sync                    │
                         │ Heartbeat               │
                         │ جمع‌آوری Metadata       │
                         └────────────┬────────────┘
                                      │
                                      ▼
                              ┌───────────────┐
                              │   WordPress   │
                              │               │
                              │ Plugins       │
                              │ Themes        │
                              │ Users         │
                              │ Configuration │
                              └───────────────┘
```

---

# چرا MLWG؟

مدیریت وضعیت امنیتی چندین WordPress معمولاً نیازمند ورود جداگانه به هر سایت است.

Administrator ممکن است مجبور باشد موارد زیر را در هر سایت بررسی کند:

- نسخه WordPress
- نسخه PHP
- افزونه‌های نصب‌شده
- قالب‌های نصب‌شده
- کاربران و Roleها
- تنظیمات
- وضعیت HTTPS
- اطلاعات Server
- Security Findings
- وضعیت اتصال

MLWG این اطلاعات را در یک **Security Console مرکزی** جمع‌آوری می‌کند.

```text
                  MLWG MANAGER
                       │
                       │ Enrollment
                       ▼
                MLWG CONNECTOR
                       │
                       ▼
                   WordPress
                       │
          ┌────────────┼────────────┐
          │            │            │
       Plugins       Themes       Users
          │            │            │
          └────────────┼────────────┘
                       │
                       │ Sync
                       ▼
                  MLWG MANAGER
```

---

# اجزای اصلی

## MLWG Manager

Manager هسته مرکزی MLWG است.

وظایف اصلی آن شامل:

- مدیریت سایت‌ها
- تولید Connector
- Enrollment
- احراز هویت
- پردازش Sync
- پردازش Heartbeat
- مدیریت Security Findings
- مدیریت Jobها
- ثبت Audit Log
- نمایش Dashboard
- ذخیره اطلاعات در SQLite

نسخه فعلی Manager بر پایه **Python 3.11+** و Python Standard Library طراحی شده است.

برای هسته اصلی Manager نیازی به Framework خارجی وجود ندارد.

---

## MLWG Connector

Connector یک افزونه PHP برای WordPress است که روی هر سایت مدیریت‌شده اجرا می‌شود.

وظایف Connector شامل:

- Enrollment
- ارتباط احراز هویت‌شده
- جمع‌آوری Metadata
- Sync سایت
- Heartbeat
- Plugin Inventory
- Theme Inventory
- User Inventory
- گزارش وضعیت WordPress
- REST Status Endpoint

Connector به‌عنوان لایه ارتباطی بین WordPress و Manager مرکزی عمل می‌کند.

---

# قابلیت‌ها

| قابلیت | وضعیت |
|---|:---:|
| مدیریت چند سایت | ✅ |
| WordPress Connector | ✅ |
| Secure Enrollment | ✅ |
| HMAC-SHA256 Authentication | ✅ |
| Replay Protection | ✅ |
| Site Sync | ✅ |
| Automatic Heartbeat | ✅ |
| جمع‌آوری WordPress Metadata | ✅ |
| Plugin Inventory | ✅ |
| Theme Inventory | ✅ |
| User Inventory | ✅ |
| ساختار Security Findings | ✅ |
| Job Center | ✅ |
| Audit Log | ✅ |
| REST Status API | ✅ |
| Dashboard مرکزی | ✅ |
| Local Security Console | ✅ |

---

# Secure Enrollment

هر WordPress از طریق یک **Enrollment Token** به Manager متصل می‌شود.

Token برای فرآیند Enrollment تولید شده و دارای زمان انقضا است.

Connector تولیدشده شامل Credentialهای حساس WordPress نیست.

Connector به اطلاعاتی مانند موارد زیر نیاز ندارد:

```text
WordPress Password
Database Password
FTP Password
SSH Password
```

فرآیند کلی Enrollment:

```text
Manager
   │
   │ تولید Installation ID
   │ تولید Enrollment Token
   ▼
Connector
   │
   │ Enrollment Request
   ▼
Manager
   │
   ▼
Site Registered
```

پس از موفقیت Enrollment، اطلاعات مورد نیاز اتصال توسط Manager نگهداری می‌شود.

---

# HMAC-SHA256 Authentication

پس از Enrollment، ارتباط بین Connector و Manager با استفاده از:

```text
HMAC-SHA256
```

احراز هویت می‌شود.

ساختار درخواست می‌تواند شامل موارد زیر باشد:

```text
Timestamp
Nonce
Request Body
Signature
Site ID
```

این معماری برای جلوگیری از درخواست‌های جعلی و ایجاد یک مکانیزم ارتباطی احراز هویت‌شده بین Connector و Manager طراحی شده است.

---

# Replay Protection

MLWG برای درخواست‌هایی که شامل Timestamp و Nonce هستند، مکانیزم Replay Protection دارد.

Manager اطلاعات Timestamp مربوط به سایت‌ها را در دیتابیس نگهداری می‌کند.

هدف این مکانیزم کاهش امکان استفاده مجدد از درخواست‌های قبلی است.

---

# Automatic Heartbeat

Connector می‌تواند به‌صورت دوره‌ای وضعیت اتصال خود را به Manager اعلام کند.

```text
Connector
    │
    │ Heartbeat
    ▼
Manager
    │
    ├── Success → Connected / Online
    │
    └── Failure → Disconnected
```

در صورت موفقیت Heartbeat، وضعیت اتصال سایت به‌روزرسانی می‌شود.

در صورت شکست ارتباط، وضعیت Connector می‌تواند به:

```text
disconnected
```

تغییر کند.

---

# جمع‌آوری اطلاعات WordPress

MLWG می‌تواند اطلاعات فنی WordPress را جمع‌آوری کند.

نمونه اطلاعات:

```text
WordPress Version
PHP Version
Operating System
Server Software
Architecture
HTTPS Status
WP_DEBUG
DISALLOW_FILE_EDIT
XML-RPC
User Registration
Multisite
Locale
Timezone
Database Driver
Database Version
```

همچنین اطلاعات زیر نیز قابل جمع‌آوری هستند:

```text
Plugins
Themes
Users
Active Theme
Cron
WordPress Configuration
```

---

# Plugin Inventory

MLWG می‌تواند اطلاعات افزونه‌های نصب‌شده WordPress را جمع‌آوری کند.

اطلاعات هر Plugin می‌تواند شامل موارد زیر باشد:

```text
Plugin Name
Version
Author
File
Active / Inactive
```

این اطلاعات به Manager منتقل شده و از طریق Console قابل مشاهده و تحلیل هستند.

---

# Theme Inventory

اطلاعات قالب‌های نصب‌شده نیز قابل جمع‌آوری است.

نمونه اطلاعات:

```text
Theme Name
Version
Author
Stylesheet
Active / Inactive
```

---

# User Inventory

MLWG امکان جمع‌آوری اطلاعات کاربران WordPress را فراهم می‌کند.

اطلاعات قابل جمع‌آوری شامل:

```text
User ID
Username
Display Name
Registration Date
Roles
```

است.

---

# Security Findings

MLWG دارای ساختاری برای ذخیره و مدیریت Security Findingها است.

هر Finding می‌تواند شامل موارد زیر باشد:

```text
Severity
Title
Detail
File
Line
Evidence
Status
Created Time
```

سطوح Severity:

```text
Critical
High
Medium
Low
```

این ساختار پایه‌ای برای توسعه Ruleهای امنیتی و قابلیت‌های تحلیلی آینده فراهم می‌کند.

---

# Job Center

MLWG دارای یک Job Center برای مدیریت عملیات مختلف است.

هر Job می‌تواند شامل اطلاعات زیر باشد:

```text
Site
Type
Status
Progress
Message
Created
Finished
```

این معماری امکان توسعه عملیات امنیتی و پردازشی بیشتر را در آینده فراهم می‌کند.

---

# Audit Log

عملیات مهم Manager در Audit Log ثبت می‌شوند.

اطلاعات Audit شامل:

```text
Site
Action
Target
Result
Timestamp
```

است.

هدف Audit Log ایجاد یک تاریخچه قابل بررسی از عملیات انجام‌شده در سیستم است.

---

# REST Status API

Connector یک REST Endpoint برای بررسی وضعیت خود ارائه می‌کند:

```text
/mlwg/v1/status
```

این Endpoint می‌تواند اطلاعاتی مانند موارد زیر را در اختیار Administrator قرار دهد:

```text
Connection Status
Site ID
Last Sync
```

---

# Dashboard

Manager دارای یک Dashboard مرکزی برای نمایش وضعیت کلی سیستم است.

مواردی مانند:

```text
Online Sites
Critical Findings
High Findings
Recent Sites
Recent Security Findings
```

در Dashboard قابل نمایش هستند.

---

# Local Security Console

Manager به‌صورت پیش‌فرض روی Localhost اجرا می‌شود:

```text
127.0.0.1:10000
```

بنابراین MLWG می‌تواند به‌عنوان یک **Local Security Console** اجرا شود.

آدرس پیش‌فرض:

```text
http://127.0.0.1:10000
```

---

# معماری امنیتی

یکی از اصول اصلی MLWG جداسازی Manager و Connector است.

```text
┌──────────────────────────────────────┐
│             MLWG MANAGER             │
│                                      │
│ Python + SQLite                      │
│ Dashboard                            │
│ Findings                             │
│ Jobs                                 │
│ Audit                                │
└──────────────────┬───────────────────┘
                   │
                   │ HMAC-SHA256
                   │ Authentication
                   ▼
┌──────────────────────────────────────┐
│            MLWG CONNECTOR            │
│                                      │
│ PHP                                  │
│ WordPress Hooks                      │
│ Metadata                             │
│ Heartbeat                            │
│ Sync                                 │
└──────────────────┬───────────────────┘
                   │
                   ▼
            ┌──────────────┐
            │  WordPress   │
            │     Site     │
            └──────────────┘
```

هنگام تولید Connector، Manager یک:

```text
Installation ID
Enrollment Token
```

اختصاصی برای نصب ایجاد می‌کند.

اطلاعات مربوط به Enrollment در Manager ذخیره می‌شوند.

---

# Privacy & Credentials

MLWG به‌گونه‌ای طراحی شده است که Credentialهای اصلی WordPress داخل Connector قرار نگیرند.

Connector تولیدشده شامل موارد زیر نیست:

```text
WordPress Password
Database Password
FTP Password
SSH Password
```

Connector صرفاً به‌عنوان لایه ارتباطی بین WordPress و MLWG Manager عمل می‌کند.

این جداسازی کمک می‌کند Credentialهای اصلی WordPress خارج از فایل Connector باقی بمانند.

---

# تکنولوژی‌ها

## Manager

```text
Python 3.11+
SQLite
HTTP Server
HTML
CSS
Python Standard Library
```

## Connector

```text
PHP
WordPress API
WordPress Hooks
WordPress REST API
WP-Cron
HMAC-SHA256
```

---

# ساختار پروژه

```text
MLWG/
│
├── mlwg.py
│
├── mlwg_data/
│   ├── mlwg.sqlite3
│   │
│   └── generated/
│       └── mlwg.php
│
├── README.md
├── README.fa.md
└── LICENSE
```

---

# نصب

## Clone کردن Repository

```bash
git clone https://github.com/Mlauncher6/MLWG.git
cd MLWG
```

## اجرای Manager

```bash
python mlwg.py
```

Manager روی آدرس زیر در دسترس خواهد بود:

```text
http://127.0.0.1:10000
```

---

# ساخت Connector

پس از اجرای Manager وارد بخش:

```text
ساخت Connector
```

شوید.

Manager یک فایل اختصاصی برای نصب تولید می‌کند:

```text
mlwg.php
```

---

# نصب Connector روی WordPress

فایل تولیدشده:

```text
mlwg.php
```

را داخل WordPress قرار داده و Plugin را فعال کنید.

پس از فعال‌سازی، Connector فرآیند Enrollment را آغاز می‌کند.

```text
WordPress
    │
    ▼
MLWG Connector
    │
    │ Enrollment
    ▼
MLWG Manager
    │
    ▼
Registered Site
```

پس از موفقیت Enrollment، سایت WordPress در Dashboard Manager نمایش داده می‌شود.

---

# وضعیت فعلی پروژه

MLWG در حال توسعه است.

معماری فعلی پایه‌ای برای توسعه یک پلتفرم گسترده‌تر در حوزه‌های زیر فراهم می‌کند:

- WordPress Security
- Security Monitoring
- Configuration Analysis
- Integrity Monitoring
- Security Findings
- Fleet Management
- Audit
- Automated Security Checks

برخی از این موارد در حال حاضر به‌عنوان قابلیت آینده یا مسیر توسعه تعریف شده‌اند و **الزاماً به معنی پیاده‌سازی کامل آن‌ها در نسخه فعلی نیستند**.

---

# Roadmap

## Core

```text
[x] Manager
[x] SQLite Database
[x] WordPress Connector
[x] Secure Enrollment
[x] HMAC Authentication
[x] Site Sync
[x] Heartbeat
[x] Plugin Inventory
[x] Theme Inventory
[x] User Inventory
[x] Security Findings Structure
[x] Job Center
[x] Audit Log
[x] Dashboard
```

## Security

```text
[ ] File Integrity Monitoring
[ ] WordPress Core Integrity Check
[ ] Plugin Integrity Check
[ ] Theme Integrity Check
[ ] Upload Security Analysis
[ ] Security Headers Analysis
[ ] REST API Security Analysis
[ ] Permission Analysis
[ ] Configuration Security Scanner
[ ] Advanced Security Rules
[ ] Automated Remediation
```

## Management

```text
[ ] Multi-User Manager
[ ] Role-Based Access Control
[ ] API Tokens
[ ] Advanced Reporting
```

---

# مسیر توسعه

MLWG با هدف تبدیل شدن از یک WordPress Fleet Manager به یک پلتفرم متمرکز مدیریت و تحلیل امنیتی WordPress طراحی شده است.

معماری فعلی بر اساس جریان زیر توسعه پیدا می‌کند:

```text
Collection
    ↓
Normalization
    ↓
Security Analysis
    ↓
Findings
    ↓
Jobs
    ↓
Audit
    ↓
Reporting
```

این ساختار امکان اضافه کردن Security Checkها و قابلیت‌های مدیریتی جدید را بدون تغییر اساسی در مدل ارتباطی Manager و Connector فراهم می‌کند.

---

# اصول امنیتی

### Separation

Manager و WordPress Connector دو بخش جداگانه هستند.

### Minimal Credentials

Connector تولیدشده به Credentialهای اصلی WordPress، Database، FTP یا SSH نیاز ندارد.

### Authenticated Communication

ارتباط‌های پس از Enrollment با HMAC-SHA256 احراز هویت می‌شوند.

### Replay Protection

Timestamp و Nonce بخشی از مکانیزم Replay Protection هستند.

### Centralized Visibility

چندین WordPress می‌توانند در یک Security Console مرکزی مدیریت شوند.

### Extensibility

ساختار Findings، Jobs و Audit امکان توسعه Ruleها و عملیات امنیتی جدید را فراهم می‌کند.

---

# مشارکت در پروژه

MLWG یک پروژه در حال توسعه است و مشارکت در آن مورد استقبال قرار می‌گیرد.

برای مشارکت:

1. Repository را Fork کنید.
2. یک Branch اختصاصی ایجاد کنید.
3. تغییرات خود را پیاده‌سازی و تست کنید.
4. یک Commit واضح ایجاد کنید.
5. Pull Request ارسال کنید.

برای تغییرات امنیتی پیشنهاد می‌شود موارد زیر در Pull Request توضیح داده شوند:

```text
Threat Model
Security Impact
Affected Component
Mitigation
Testing
```

---

# License

MLWG تحت مجوز:

**MIT License**

منتشر می‌شود.

متن کامل مجوز در فایل زیر قرار دارد:

```text
LICENSE
```

---

# MLUNCHER

<p align="center">
  <strong>MLUNCHER WORDPRESS GUARD</strong>
</p>

<p align="center">
  مدیریت، پایش و تحلیل متمرکز امنیت WordPress
</p>

```text
MLWG
MLUNCHER WORDPRESS GUARD
```

<p align="center">
  <a href="README.md">🇬🇧 مشاهده نسخه انگلیسی</a>
</p>
