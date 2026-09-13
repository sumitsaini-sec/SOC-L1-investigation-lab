# Upload Sentinel Desk to GitHub

This is the complete source for the published app, including tests, the dependency lockfile and database migrations. It excludes installed dependencies, generated builds, personal investigation data and the original deployment identity.

## Upload with Git

Create an empty repository named `sentinel-desk-soc-lab` in your GitHub account. Do not initialize it with a README because this project already includes one. Open a terminal in this extracted project folder, replace `YOUR_USERNAME`, and run:

```bash
git init -b main
git add .
git commit -m "Publish Sentinel Desk SOC investigation lab"
git remote add origin https://github.com/YOUR_USERNAME/sentinel-desk-soc-lab.git
git push -u origin main
```

If Git asks for your name and email, configure your own Git identity before committing. Authenticate with GitHub through its normal sign-in flow; do not put passwords or access tokens into source files.

## Run and verify

Install Node.js 24, then use the commands in README.md:

```bash
npm ci
npm run test:acceptance
npm run build
npm run db:local
npm start
```

Open the local address printed by the app. Its first visit generates 600 corrected baseline alerts. Retain local database storage to preserve your local progress.

## Repository description

SOC L1 investigation lab with 600 alerts, linked SIEM/EDR/IOC evidence, persistent investigations, evidence-based feedback, retry history and Markdown case reports.

Suggested topics: `soc`, `blue-team`, `cybersecurity`, `siem`, `edr`, `incident-response`, `typescript`, `react`.

## Portfolio use

Upload the extracted source folder, not only this ZIP. Investigation records remain in the app database; they are not automatically published to GitHub. Export selected completed investigations as Markdown from the app and add them to an `investigations/` folder if you want to demonstrate your work.

The app needs a server and SQLite/D1 database; uploading source is separate from hosting a running app. Check the hosted app's current sharing settings before advertising it as a public demo.
