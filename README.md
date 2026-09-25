<p align="center">
  <strong>🇬🇧 English</strong>
  &nbsp;&nbsp;•&nbsp;&nbsp;
  <a href="README.fa.md">🇮🇷 فارسی</a>
</p>

<h1 align="center">MLUNCHER WORDPRESS GUARD</h1>

<p align="center">
  <strong>MLWG</strong> — Centralized security management, monitoring and analysis for WordPress fleets.
</p>

<p align="center">
  <code>MLUNCHER WORDPRESS GUARD</code>
</p>

---

## Overview

**MLUNCHER WORDPRESS GUARD (MLWG)** is a centralized security management and monitoring system designed for managing multiple WordPress installations from a single security console.

Instead of being only a traditional WordPress plugin, MLWG consists of two main components:

- **MLWG Manager** — Central management console written in Python
- **MLWG Connector** — PHP plugin installed on WordPress

The Manager and Connector communicate through a controlled **Enrollment, Sync and Heartbeat** workflow.

The system is designed to collect technical and security-related information from WordPress installations and make that information available through a centralized management interface.

---

## Architecture

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
                              Authenticated
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │     MLWG CONNECTOR      │
                         │                         │
                         │ PHP / WordPress        │
                         │ Enrollment              │
                         │ Sync                    │
                         │ Heartbeat               │
                         │ Metadata Collection     │
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

# Why MLWG?

Managing the security state of multiple WordPress installations normally requires accessing each website separately.

An administrator may need to inspect:

- WordPress version
- PHP version
- Installed plugins
- Installed themes
- Users and roles
- Configuration
- HTTPS status
- Server information
- Security findings
- Connection status

MLWG centralizes this information inside one management console.

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

# Core Components

## MLWG Manager

The Manager is the central component of MLWG.

It is responsible for:

- Site management
- Connector generation
- Enrollment
- Authentication
- Sync processing
- Heartbeat processing
- Security findings
- Job management
- Audit logging
- Dashboard presentation
- SQLite storage

The current Manager is designed around **Python 3.11+** and the Python Standard Library.

No external framework is required for the core Manager implementation.

---

## MLWG Connector

The Connector is a PHP-based WordPress plugin that runs on each managed WordPress installation.

Its responsibilities include:

- Enrollment
- Authenticated communication
- Metadata collection
- Site synchronization
- Heartbeat
- Plugin inventory
- Theme inventory
- User inventory
- WordPress status reporting
- REST status endpoint

The Connector acts as the communication layer between WordPress and the central Manager.

---

# Feature Matrix

| Feature | Status |
|---|:---:|
| Multi-Site Management | ✅ |
| WordPress Connector | ✅ |
| Secure Enrollment | ✅ |
| HMAC-SHA256 Authentication | ✅ |
| Replay Protection | ✅ |
| Site Sync | ✅ |
| Automatic Heartbeat | ✅ |
| WordPress Metadata Collection | ✅ |
| Plugin Inventory | ✅ |
| Theme Inventory | ✅ |
| User Inventory | ✅ |
| Security Findings Structure | ✅ |
| Job Center | ✅ |
| Audit Log | ✅ |
| REST Status API | ✅ |
| Central Dashboard | ✅ |
| Local Security Console | ✅ |

---

# Secure Enrollment

Each WordPress installation is connected to the Manager through an **Enrollment Token**.

The token is generated for the enrollment process and has an expiration period.

The generated Connector does **not** contain sensitive WordPress credentials.

The Connector does not require credentials such as:

```text
WordPress Password
Database Password
FTP Password
SSH Password
```

The general enrollment flow is:

```text
Manager
   │
   │ Generate Installation ID
   │ Generate Enrollment Token
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

After successful enrollment, the Manager stores the required enrollment information for the installation.

---

# HMAC-SHA256 Authentication

After enrollment, communication between the Connector and Manager uses:

```text
HMAC-SHA256
```

for request authentication.

A request can contain information such as:

```text
Timestamp
Nonce
Request Body
Signature
Site ID
```

The authentication design is intended to prevent unauthorized or forged requests and provide an authenticated communication mechanism between the Connector and Manager.

---

# Replay Protection

MLWG includes a replay protection mechanism for requests containing timestamp and nonce information.

The Manager maintains timestamp information for individual sites in the database.

The purpose of this mechanism is to reduce the possibility of previously captured requests being reused.

---

# Automatic Heartbeat

The Connector can periodically report its connection state to the Manager.

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

Successful heartbeat requests update the site's connection state.

Communication failures can cause the Connector status to become `disconnected`.

---

# WordPress Metadata Collection

MLWG can collect technical information from a WordPress installation.

Collected metadata may include:

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

Additional WordPress information can include:

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

MLWG can collect information about installed WordPress plugins.

Plugin inventory information may include:

```text
Plugin Name
Version
Author
File
Active / Inactive
```

This information is synchronized with the Manager and can be viewed and analyzed from the central console.

---

# Theme Inventory

MLWG can collect information about installed WordPress themes.

Theme information may include:

```text
Theme Name
Version
Author
Stylesheet
Active / Inactive
```

---

# User Inventory

MLWG can collect WordPress user inventory information.

Collected information may include:

```text
User ID
Username
Display Name
Registration Date
Roles
```

---

# Security Findings

MLWG provides a structure for storing and managing security findings.

A finding can contain information such as:

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

Supported severity levels include:

```text
Critical
High
Medium
Low
```

The findings structure provides a foundation for future security rules and analysis capabilities.

---

# Job Center

MLWG includes a Job Center for managing system operations.

A Job can contain:

```text
Site
Type
Status
Progress
Message
Created
Finished
```

The Job architecture provides a foundation for expanding MLWG with additional security and processing operations.

---

# Audit Log

Important Manager operations can be recorded in the Audit Log.

Audit information includes:

```text
Site
Action
Target
Result
Timestamp
```

The purpose of the Audit Log is to provide a traceable history of operations performed through the management system.

---

# REST Status API

The Connector provides a REST endpoint for checking its current status:

```text
/mlwg/v1/status
```

The endpoint can expose information such as:

```text
Connection Status
Site ID
Last Sync
```

This endpoint is intended for administrative status inspection.

---

# Dashboard

The Manager provides a centralized dashboard for displaying the overall state of the managed WordPress fleet.

Dashboard information can include:

```text
Online Sites
Critical Findings
High Findings
Recent Sites
Recent Security Findings
```

---

# Local Security Console

The Manager runs on localhost by default:

```text
127.0.0.1:10000
```

This allows MLWG to operate as a local security management console.

Default URL:

```text
http://127.0.0.1:10000
```

---

# Security Architecture

A key architectural principle of MLWG is the separation between the central Manager and the WordPress Connector.

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

When a Connector is generated, the Manager assigns an installation-specific:

```text
Installation ID
Enrollment Token
```

Enrollment information is stored by the Manager.

---

# Privacy & Credentials

MLWG is designed so that the Connector does not contain the primary credentials of the WordPress installation.

The generated Connector does not include:

```text
WordPress Password
Database Password
FTP Password
SSH Password
```

The Connector operates as a communication layer between the WordPress installation and the MLWG Manager.

This separation helps keep primary WordPress credentials outside the generated Connector.

---

# Technology Stack

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

# Project Structure

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

# Installation

## Clone the Repository

```bash
git clone https://github.com/Mlauncher6/MLWG.git
cd MLWG
```

## Start the Manager

```bash
python mlwg.py
```

The Manager will be available at:

```text
http://127.0.0.1:10000
```

---

# Generate a Connector

Open the Manager dashboard and navigate to:

```text
Create Connector
```

The Manager generates an installation-specific file:

```text
mlwg.php
```

---

# Install the Connector

Place the generated:

```text
mlwg.php
```

file into the WordPress installation and activate the plugin.

After activation, the Connector starts the enrollment process.

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

After successful enrollment, the WordPress site becomes available inside the Manager dashboard.

---

# Current Project Status

MLWG is currently under active development.

The current architecture provides a foundation for a broader WordPress security platform covering areas such as:

- WordPress Security
- Security Monitoring
- Configuration Analysis
- Integrity Monitoring
- Security Findings
- Fleet Management
- Audit
- Automated Security Checks

Some of these areas are currently defined as future capabilities or architectural expansion points and **do not necessarily mean that they are fully implemented in the current version**.

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

# Development Direction

MLWG is designed to evolve from a centralized WordPress fleet manager into a broader security management and analysis platform.

The current architecture is designed around a modular flow:

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

This structure provides a foundation for adding additional security checks and management capabilities without fundamentally changing the Manager/Connector communication model.

---

# Security Principles

### Separation

The Manager and WordPress Connector are separate components.

### Minimal Credentials

The generated Connector does not require primary WordPress, database, FTP or SSH credentials.

### Authenticated Communication

Post-enrollment communication uses HMAC-SHA256 authentication.

### Replay Protection

Timestamp and nonce information are used as part of the replay protection mechanism.

### Centralized Visibility

Multiple WordPress installations can be represented inside one central security console.

### Extensibility

The Findings, Jobs and Audit architecture provides a foundation for additional security rules and operations.

---

# Contributing

MLWG is an evolving project and contributions are welcome.

To contribute:

1. Fork the repository.
2. Create a dedicated branch.
3. Implement and test your changes.
4. Create a clear commit.
5. Open a Pull Request.

For security-related changes, contributors are encouraged to document:

```text
Threat Model
Security Impact
Affected Component
Mitigation
Testing
```

---

# License

MLWG is released under the **MIT License**.

See:

```text
LICENSE
```

for the full license text.

---

# MLUNCHER

<p align="center">
  <strong>MLUNCHER WORDPRESS GUARD</strong>
</p>

<p align="center">
  Centralized WordPress security management, monitoring and analysis.
</p>

```text
MLWG
MLUNCHER WORDPRESS GUARD
```

<p align="center">
  <a href="README.fa.md">🇮🇷 Read this README in Persian</a>
</p>
