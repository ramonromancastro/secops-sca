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
*   **Automated Scanning**: Built-in cron jobs automatically re-scan environments every 6 hours.
*   **Dual Token Security**: Role-Based Access Control (RBAC) supporting Global Admin Tokens and specific Upload Tokens for CI/CD pipelines, managed through an elegant UI Auth Modal.

## 🏗️ Architecture

The platform is divided into three main layers:

1.  **Frontend (Vue 3 + TailwindCSS)**: A reactive Single Page Application (SPA) served statically. It handles UI rendering, dark/light mode switching, and token-based API authentication.
2.  **Backend (FastAPI + Uvicorn)**: A high-concurrency async Python API. It manages file parsing, interacts with the OSV.dev API, calculates CVSS security scores, and handles authentication.
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

   Open your browser and navigate to ```http://<YOUR-SERVER-IP>:/sca```

## 🛡️ Authentication & Usage

Upon first accessing the dashboard, you will be prompted to enter your **API Bearer Token**.
You can find the automatically generated tokens inside your server at: ```/opt/sca/config/settings.json```

**Uploading Manifests**: Click the "+ Subir Manifiesto" button on the UI, or send a POST request to ```/api/upload``` via your CI/CD pipelines using the ```upload_token```.

**Forcing Scans**: Click "Forzar Escaneo Global" to immediately re-check all known dependencies against the OSV database.

## 🤖 AI Acknowledgment

This project was ideated, architected, and developed with the assistance of Artificial Intelligence. AI tools (specifically Google's Gemini) acted as an advanced pair-programming partner, helping to optimize the database-less architecture, design the reactive Vue 3 UI, implement strict SELinux security policies, and refactor the bash deployment pipeline.

The human-AI collaboration significantly accelerated the development cycle while maintaining enterprise-grade security and coding standards.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
Copyright © 2026 rrc2software.
