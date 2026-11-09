# SecOps SCA Monitor - Enterprise Security Dashboard

![GitHub Release](https://img.shields.io/github/v/release/ramonromancastro/secops-sca?include_prereleases&color=blue&sort=date)
![Downloads](https://img.shields.io/github/downloads/ramonromancastro/secops-sca/total?color=brightgreen)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python](https://img.shields.io/badge/Python-3.11%2B-blueviolet)
![Vue.js](https://img.shields.io/badge/Vue.js-3.x-4FC08D)

**SecOps SCA Monitor** is a lightweight, high-performance Software Composition Analysis (SCA) platform. Designed for enterprise security teams, it provides continuous monitoring of third-party dependencies without the overhead of maintaining a database.

## 🚀 Key Features

*   **100% Database-less Architecture**: State is entirely managed via the local file system (JSON manifestations and reports), atomic synchronization, and async batch processing.
*   **Multi-Ecosystem Support**: Seamlessly parses `composer.lock` (PHP), `Gemfile.lock` (Ruby), `package-lock.json` (Node.js), `requirements.txt` (Python), and `pom.xml` (Java Maven).
*   **Real-time OSV.dev Integration**: Asynchronously checks dependencies against the Open Source Vulnerability (OSV) database for zero-day and historical CVEs.
*   **Executive Dashboard**: Built with Vue 3 and Chart.js, featuring Security Scores, Ecosystem Distribution, and Historic Trend tracking.
*   **Safe, bounded scans**: Project results are combined across uploaded manifests, saved atomically, and scanned with bounded OSV API concurrency.
*   **Dual Token Security**: Role-Based Access Control (RBAC) supporting Global Admin Tokens and specific Upload Tokens for CI/CD pipelines, managed through an elegant UI Auth Modal.

## 🏗️ Architecture

The platform is divided into three main layers:

1.  **Frontend (Vue 3 + TailwindCSS)**: A reactive Single Page Application (SPA) served statically. It handles UI rendering, dark/light mode switching, and token-based API authentication.
2.  **Backend (FastAPI + Uvicorn)**: An async Python API. It manages file parsing, interacts with OSV.dev, handles authentication, and computes CVSS v3.0/v3.1 Base Scores and CVSS v4.0 scores from complete vectors when OSV does not provide a numeric score. CVSS v3 vectors with Temporal or Environmental metrics are not reduced to Base Scores.
3.  **Infrastructure (Apache + Systemd)**: Apache acts as a reverse proxy, handling static file delivery and forwarding API requests. Systemd daemonizes the FastAPI application, ensuring continuous uptime.

## ⚙️ Installation

The project includes an automated deployment script tailored for Debian/Ubuntu and RHEL/AlmaLinux/Rocky systems.

### Prerequisites
* A Linux-based server (Debian/Ubuntu or RHEL family)
* `root` or `sudo` privileges

### Quick Deployment
1. Download the deployment script:
   ```bash
   wget [https://raw.githubusercontent.com/ramonromancastro/secops-sca/main/deploy.sh](https://raw.githubusercontent.com/ramonromancastro/secops-sca/main/deploy.sh)
   chmod +x deploy.sh

2. Run the automated installer (it will download the latest release automatically):
   ```bash
   sudo ./deploy.sh --download latest
   ```
   (Optional) You can customize the deployment path, port, or alias:

   ```bash
   sudo ./deploy.sh --download latest --app-dir /opt/my-sca --port 8080 --alias /security
   ```

3. Access the Dashboard:

   Open your browser and navigate to ```http://<YOUR-SERVER-IP>:/secops-sca```

### User configuration (`config/settings.json`)

This file contains only parameters intended for administrator customization. The deployment creates it with defaults and preserves it during upgrades.

#### Modifiable Parameters

*   **`cron_schedule`**: Defines the frequency of automatic global scans using standard cron syntax.
    *   *Default:* `"0 */6 * * *"` (Every 6 hours).
*   **`relative_url_root`**: The base path (alias) where the application is served via the reverse proxy (e.g., Apache or Nginx). This must match the alias configured in your web server.
    *   *Default:* `"/secops-sca"`
*   **`scan_history_size`**: The maximum number of historical scan data points to retain and display in the dashboard's trend chart.
    *   *Default:* `15`
*   **`scan_batch_size`**: The number of projects processed concurrently when a global scan is triggered. The backend clamps this setting to the range 1–10.
    *   *Default:* `10`

### System-managed state (`config/system_state.json`)

The backend creates and maintains this file. It is separate from user configuration and should not be edited as part of routine setup. It contains:

*   API and upload tokens, generated on first deployment.
*   `last_global_scan` and `scan_history`, updated by scans.
*   `ignored_vulnerabilities_by_project`, updated by the dashboard's ignore actions.
*   `vulnerability_lifecycle`, which tracks first observation and subsequent resolution observations for MTTR and aging.

On upgrade, the backend migrates these system-managed values out of an older combined `settings.json` without changing the existing tokens or losing scan history and project ignores. The state file is created with owner-only permissions by deployment.

### Scan coverage and limits

* Uploads are limited to 5 MiB and 1,000 parsed dependencies per manifest.
* `composer.lock`, `Gemfile.lock`, and `package-lock.json` provide resolved versions and are preferred. `composer.json` is accepted only when its Packagist requirements are exact pins; version ranges require `composer.lock`.
* `requirements.txt` accepts exact `==` pins. Included files, editable requirements, and ranges must be resolved before upload.
* `pom.xml` scans direct project dependencies with explicit or locally defined property versions. It does not resolve transitive dependencies, profiles, BOMs, or inherited dependency management. Use an effective Maven dependency inventory for complete coverage.
* When coverage is limited, the dashboard displays a warning. A scan with malformed or incomplete OSV responses is reported as failed/partial and does not overwrite that manifest's prior successful result.
* OSV receives package names, ecosystems, and versions to perform vulnerability matching. Do not upload manifests containing data that your organization does not permit sending to this service.

### Same-origin deployment

Apache serves the frontend and proxies API requests through the same origin. The backend therefore does not enable CORS or require a `SECOPS_CORS_ORIGINS` environment variable.

### Dashboard views and metric definitions

The dashboard has four primary navigation areas: Executive Dashboard, Intelligence Center, Asset Inventory, and Vulnerability Inventory. Project details remain a contextual view and can be opened from risk and inventory rows; navigation uses the URL fragment so browser back/forward and direct project links work without changing the project detail workflow.

* Global severity totals count unique advisory identifiers. Ignored findings remain project-scoped and are shown separately; the same advisory can be ignored in one project and active in another.
* The Vulnerability Inventory groups findings by ecosystem, advisory, and dependency. It supports severity, text, ecosystem, active/ignored, and fixed-version filters, pagination, project drill-down, and per-project or global restoration of ignored advisories.
* Quick-win totals count active project/package exposures with a fixed version declared by OSV. “No fixed version declared” means the advisory data does not declare a fixed version; it does not prove that no patch exists and is not a zero-day classification.
* Historical project-average scores are stored starting with new global scans. Older history entries retain severity totals but have no score snapshot.
* Aging starts when the system first observes a finding after lifecycle tracking is enabled. Older saved findings are marked “not tracked” until the next successful scan. MTTR uses only tracked findings later absent from a successful scan; deleting a project or manifest is excluded from remediation time.

The UI uses authenticated aggregate endpoints for executive and intelligence views, paginated /api/projects and /api/vulnerabilities endpoints for the inventories, and /api/projects/{project} to load one project's detail on demand.

## 🛡️ Authentication & Usage

Upon first accessing the dashboard, you will be prompted to enter your **API Bearer Token**.
The automatically generated tokens are stored in ```/opt/secops-sca/config/system_state.json```.

**Uploading Manifests**: Click the "+ Subir Manifiesto" button on the UI, or send a POST request to ```/api/upload``` via your CI/CD pipelines using the ```upload_token```.

**Forcing Scans**: Click "Forzar Escaneo Global" to immediately re-check all known dependencies against the OSV database.

## 🤖 AI Acknowledgment

This project was ideated, architected, and developed with the assistance of Artificial Intelligence. AI tools (specifically Google's Gemini) acted as an advanced pair-programming partner, helping to optimize the database-less architecture, design the reactive Vue 3 UI, implement strict SELinux security policies, and refactor the bash deployment pipeline.

The human-AI collaboration significantly accelerated the development cycle while maintaining enterprise-grade security and coding standards.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
Copyright © 2026 rrc2software.
