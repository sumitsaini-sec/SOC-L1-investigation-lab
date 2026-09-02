# SOC L1 Investigation Lab v3

A browser-based **SOC Level 1 investigation simulator** designed for cybersecurity students and junior SOC analysts. It runs locally with synthetic training data and does not require a backend or internet connection.

## Highlights

- 560 independently generated alerts across 16 detection scenarios
- Unique timestamps, counts, IPs, users, hosts, risk scores, severity, event volume and evidence for every case
- Persistent investigation progress using browser local storage
- Add custom alerts from the dashboard
- Search plus severity, status and complexity filters
- Investigation workflow with Overview, Timeline, Process, Network, Authentication, Intel/IP, Scope & Impact and Raw Logs
- Investigation-readiness checklist that requires evidence review before case submission
- Source/IOC reputation assessment, endpoint-impact assessment and compromise validation
- Asset criticality, EDR state, identity privilege/MFA context and correlated blast radius
- True Positive / False Positive / Needs More Investigation classification
- Seven realistic L1 actions including containment, account disablement, IOC blocking, escalation and enrichment
- Six-part decision scoring with evidence-based analyst notes
- Investigation History page
- Escalated Incidents page
- Detection Engineering view with rule performance, MITRE mapping, log-source health, coverage and ingestion latency
- MITRE ATT&CK coverage generated from the live queue
- Export/Import progress as JSON
- Automatic upgrade of saved v2 cases with fresh v3 evidence
- Fully client-side: HTML, CSS and vanilla JavaScript

## Run Locally

1. Download or clone this repository.
2. **Windows recommended:** double-click `start_server.bat`, then use `http://localhost:8000`.
3. Or open `index.html` directly in Chrome, Edge or Firefox.
4. Start investigating alerts.

No npm install or database is required. The included local server launcher uses Python if available and gives browser storage a stable localhost origin.

## Persistent Progress

The app automatically stores the current alert queue, evidence-review progress, investigation decisions, notes and status changes in the browser using `localStorage`.

When you reopen the same project in the same browser/origin, investigated alerts remain investigated. For a portable backup, use **Export Progress** and later **Import Progress**.

> Browser storage is device/browser specific. If you publish the project to GitHub Pages, progress remains local to each visitor's browser.

## GitHub Pages

Because this is a static project, it can be hosted directly with GitHub Pages:

1. Push the files to a GitHub repository.
2. Open repository **Settings → Pages**.
3. Under **Build and deployment**, choose **Deploy from a branch**.
4. Select your main branch and `/ (root)`.
5. Save. GitHub will provide the public site URL.

## Project Structure

```text
.
├── index.html      # Dashboard and investigation UI
├── styles.css      # Responsive SOC dashboard styling
├── app.js          # Alert generation, investigation logic and persistence
├── README.md       # Project documentation
├── LICENSE         # MIT License
└── .gitignore
```

## Training Disclaimer

All alerts, IP addresses, users, hosts and threat-intelligence results in this project are **synthetic training data**. This project is for defensive cybersecurity education and portfolio demonstration.

## Suggested Portfolio Description

> Built a local SOC L1 investigation simulator with 560 unique cases across 16 detection scenarios, IOC enrichment, endpoint and identity context, process/network/authentication/raw-log correlation, MITRE ATT&CK mapping, persistent case history and graded incident escalation using HTML, CSS and vanilla JavaScript.

## Future Ideas

- CSV/Sysmon log import
- Sigma/YARA rule import
- PCAP and EVTX training datasets
- Case assignment and SLA timers
- Light/dark themes
- Optional backend for multi-user training
