# Sentinel Desk — SOC Investigation Lab

A complete, persistent SOC L1 training application for investigating an enterprise telemetry snapshot. Work through linked identity, endpoint, network and email records; document a defensible conclusion; and receive feedback after submission.

## What is included

- **600 baseline alerts**, **14,441 correlated records**, **240 endpoints**, **120 identities**, **91 detection rules**, and **24 multi-stage incident groups**.
- Twenty workspaces: overview, alerts, incidents, SIEM, EDR, endpoints, identities, network/DNS, email, IOC investigation, intelligence, cases, notes, rules, MITRE, reports, history, performance, tools and settings.
- Four ground-truth outcomes: true positive, false positive, benign positive and insufficient evidence. Three difficulty levels affect evidence depth. Both remain server-side until assessment submission.
- Authenticated-user scoped investigations, bookmarks, cases, response actions and preferences. Database-backed state survives refresh and restart. Unsaved worksheet changes also have a browser recovery draft.
- Configurable scenario injection with a reproducible evidence seed, detection, severity, difficulty, user, endpoint, IOC and time.
- Searchable inventory, working entity pivots, paginated SIEM results, process ancestry, raw records, email headers, provider observations, case exports and progress exports.
- Twelve analyst utilities: IP reputation, WHOIS, DNS, domain age, URL and hash analysis; Base64, URL, header and JWT decoding; timestamp conversion; bounded regex testing.

## Start an investigation

1. Open **Alert queue** and choose **ALT3-00001 — Suspicious login sequence**.
2. Read the timeline. Inspect authentication failures, subsequent success and execution records. Open a record and **Bookmark evidence**.
3. **Enrich source IP** and compare provider observations. **Inspect identity** to review baseline country, working hours, device trust, MFA and historical authentication.
4. **Search SIEM** for the IP, pivot to the endpoint's process tree, and inspect DNS and outbound connections. The green context bar keeps every pivot attached to the active investigation.
5. Review the incident timeline and related scope. Preserve relevant evidence, including business context that may establish authorization or contradict an aggregate detection.
6. Complete the **Investigation worksheet**, choose a verdict and justified disposition, and **Create case** for an escalation. Notes autosave; navigation waits for a pending worksheet save.
7. If appropriate, record a reasoned simulated response action. It changes the lab's response state and audit log.
8. **Submit assessment**. Submission locks the assessment and reveals the explanation, difficulty, skill dimensions and improvement points. View the results in history and performance.

## Corrected exercises, retries and reports

The current hardened dataset is **v3** and uses `ALT3-` identifiers, varied causal timelines, executable-specific command syntax, distinct process-image/artifact/attachment hashes, Linux endpoints for sudo, and protocol-correct remote ports. Earlier `ALT-` and `ALT2-` exercises plus all analyst work remain preserved; historical pages can resolve forward to the v3 corrected exercise. Initialization never overwrites prior investigations or raw evidence.

- **Reliable saves:** bookmarks are stored as independent relational rows keyed by analyst + alert + attempt + event, so simultaneous bookmark requests merge instead of replacing one JSON array with another. Source visits use atomic field updates. Worksheet and case versions reject stale saves from another tab. Browser recovery drafts and explicit export/reload controls preserve conflicting work.
- **Optional hints:** three investigation prompts; assisted attempts are labelled in history. No verdict is revealed.
- **Retry:** after submission, start a new attempt. Previous notes, raw records, bookmarks, case, response log and result are archived together. The new attempt starts with a blank worksheet and the alert's severity.
- **Relationships:** incident stages and related scope include clickable user, endpoint, process and destination relationships, each with a supporting record. Association does not establish compromise.
- **Handoff:** “Update handoff from investigation” synchronizes summary, verdict, preserved evidence **and investigation severity/priority** while preserving additional case notes. The SLA policy is explicit: deadlines recalculate from original case creation (Critical 1h, High 4h, Medium 24h, Low 48h), and changes are recorded in SLA history.
- **Markdown:** current and archived attempts export GitHub-ready reports with escalation rationale, scope, record references, raw evidence, response log and submitted feedback.

## Local installation

Requires Node.js **22.13+** (Node 24 recommended) and npm. No API key, live threat feed, paid service or external database is required for local use.

```bash
npm ci
npm run build
npm run db:local
npm start
```

Open the local URL printed by Wrangler (normally `http://127.0.0.1:8787`). The first visit creates the deterministic corpus in resumable batches. Subsequent visits reuse the existing database. Local data lives in `.wrangler/state`; retain that directory to retain progress. The ignored execution profile defaults to portable mode on a fresh clone. Sites supplies its own authenticated identity and managed database when hosted.

For UI development, initialize the database after the first build, then use `npm run dev`. To evolve the schema, edit `db/schema.ts`, run `npm run db:generate`, inspect the generated SQL, and apply local migrations with `npm run db:local`. Schema migrations contain no generated seed data.

## SIEM query examples

```text
event_id = 4625
host = "FIN-LT-001" AND kind = "process"
source_ip = "203.0.113.20" OR destination_ip = "203.0.113.20"
Events | where domain contains "sync" | sort by timestamp desc | take 50
```

Supported fields: `alert_id`, `incident_id`, `timestamp`, `kind`, `event_id` / `eventid`, `user` / `username`, `host` / `hostname`, `source_ip`, `destination_ip`, `domain`, `hash`, `process_name` / `process`, `source`, `severity`, `outcome`. Operators: `=`, `==`, `!=`, `contains`, `AND`, `OR`. SQL operator precedence applies: AND before OR. Parenthesized expressions and full KQL are intentionally outside this parser. Unknown fields and unsupported syntax produce an explicit error. Plain text searches the normalized record JSON. The time filters use UTC; display preferences can show a different timezone.

## Architecture

React 19 and TypeScript run on Vinext/Vite. The interface uses Tailwind 4, shadcn/ui, Radix primitives, Lucide and Recharts. The API runs on a Cloudflare-compatible Worker using prepared D1/SQLite statements. Drizzle owns the schema and migrations.

```text
components/lab/       Workspace shell, investigation and evidence interfaces
lib/lab/catalog.ts   Detection definitions and analyst field labels
lib/lab/entities.ts  Shared enterprise inventory and identity baselines
lib/lab/scenario-*   Deterministic scenario generation and category evidence
lib/lab/query.ts     Whitelisted, parameterized SIEM query parser
lib/lab/scoring.ts   Validation and transparent assessment rubric
lib/lab/store.ts     Resumable seed, entity persistence and analyst state
app/api/lab/         Read/search and investigation mutation API
db/ + drizzle/      Schema and schema-only migrations
tests/              Full application API acceptance harness
```

The relational model links alerts to users, hosts, rules and optional incident groups. Events refer to alerts and incident groups; searchable columns are indexed while complete source records remain JSON. IOC records are shared observations, with MD5/SHA1 aliases linked to SHA256 metadata. Private `scenario_truth` rows are used only for grading. Analyst state is keyed by authenticated owner plus alert ID. Actions and cases are also owner scoped.

Seed batches are idempotent. Baseline scenario numbers and seed determine the evidence. Custom injection uses a stable seed to generate evidence and a new identifier to permit repeating the exercise. Changing a category or override changes the resulting scenario. Case assignment is a training field, not a notification or permission grant.

## Evidence and grading

Windows examples include 4624, 4625, 4634, 4648, 4672, 4688, 4697, 4698, 4720, 4728, 4732, 4740, 4768, 4769 and 4776; Sysmon/file/network context supplements the security log. Process records expose PID, PPID, command line, path, hashes, signature and connection context. Auth records include logon type, package, MFA, device trust and session correlation.

Scoring weights: verdict 25%, key evidence 15%, evidence analysis 30% (IOC, endpoint, identity, network, context and email where applicable), scope 10%, documentation 10%, disposition 10%. Analysis checks a recorded source visit, valid bookmarked record references, scenario-specific tokens and overlap with the actual observation/interpretation for that record. `Evidence Reviewed` must cite at least two bookmarked event IDs. Repeated filler and duplicate core paragraphs are rejected, generic prose cannot earn full analysis credit, and fact contradictions cap the score. This remains a transparent evidence-matching heuristic, not comprehensive semantic or human grading. Investigation time is wall-clock time from first review to submission and includes pauses. The reference chart shows 24 hours ending at the newest scenario detection; it is a training snapshot rather than a live feed.

Synthetic reputation is never a substitute for behavioral evidence. Authenticated malicious mail and harmless sender-authentication failures are both represented. Approved change records distinguish correctly detected authorized activity from detection errors. Collection gaps preserve uncertainty.

## Verification

```bash
npm run test:acceptance
npx tsc --noEmit
npm run build
```

The acceptance harness runs the real API against a SQLite adapter for D1. It verifies seed cardinality and idempotency, hidden truth, identity/IP/endpoint/network pivots, query rejection and pagination, bookmarks, draft persistence, case gates, response audit writes, submission scoring and locking, owner isolation, chart records and coherent scenario injection. Regression tests cover normalized simultaneous bookmarks/source updates, stale writes, anti-gaming scoring, case-insensitive and defanged IOC normalization, executable-specific commands, separate object hashes and varied timing across 600 scenarios, Linux/RDP consistency, severity inheritance, SLA recalculation/history, handoff refresh, retry archives, Markdown export, seed zero and preservation of earlier work. The documented reference investigation achieves 100/100. Automated acceptance uses the real API and SQLite; final browser QA may depend on browser availability.

## Portfolio walkthrough and screenshots

Suggested walkthrough: operations overview → ALT3-00001 timeline → identity baseline → process tree → network evidence → worksheet → case handoff → assessment feedback. Capture screenshots from those actual application screens at 1440px desktop width and one narrow mobile viewport. No screenshots are fabricated or included as stand-ins for functionality.

The app uses synthetic users, `.test` domains, documentation-only public IP ranges, invented file hashes and inert command-line evidence. It does not execute suspicious commands, fetch indicator URLs, send email, or operate real endpoints. Decoding utilities display text without execution; regex runs in a disposable worker with a 500 ms timeout. JWT decoding explicitly does not verify a signature. Production access is private to the workspace owner by default. This is a training environment, not a production security control or an anti-cheat exam; source access exposes the scenario generator.
