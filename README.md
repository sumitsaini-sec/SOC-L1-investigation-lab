# SOC L1 Local Practice Lab

A browser-based **SOC Level 1 investigation simulator** designed for cybersecurity students and junior SOC analysts. It runs locally with synthetic training data and does not require a backend or internet connection.

## Highlights

- 560 synthetic alerts on first launch
- Persistent investigation progress using browser local storage
- Add custom alerts from the dashboard
- Search, severity/status filters and pagination
- Investigation workflow with Overview, Timeline, Process Tree, Network, Authentication Logs and Threat Intelligence
- True Positive / False Positive / Needs More Investigation classification
- L1 actions: escalate, close false positive, request enrichment or monitor
- Analyst notes, decision scoring and investigation timestamps
- Investigation History page
- Escalated Incidents page
- MITRE ATT&CK training coverage
- Export/Import progress as JSON
- Fully client-side: HTML, CSS and vanilla JavaScript

## Run Locally

1. Download or clone this repository.
2. **Windows recommended:** double-click `start_server.bat`, then use `http://localhost:8000`.
3. Or open `index.html` directly in Chrome, Edge or Firefox.
4. Start investigating alerts.

No npm install or database is required. The included local server launcher uses Python if available and gives browser storage a stable localhost origin.

## Persistent Progress

The app automatically stores the current alert queue, investigation decisions, notes and status changes in the browser using `localStorage`.

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

> Built a local SOC L1 investigation simulator with 500+ synthetic alerts, persistent case history, MITRE ATT&CK context, process/network/authentication evidence, analyst notes, incident escalation and decision scoring using HTML, CSS and vanilla JavaScript.

## Future Ideas

- CSV/Sysmon log import
- Sigma-style detection rules
- More incident scenarios
- Case assignment and SLA timers
- Light/dark themes
- Optional backend for multi-user training
