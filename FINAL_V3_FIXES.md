# Final v3 fixes

| Review finding | Final v3 change |
| --- | --- |
| Simultaneous bookmarks could overwrite each other | Bookmarks are independent rows in `investigation_bookmarks`; concurrent selections merge safely. |
| Generic/filler notes could reach 100/100 | Grading now requires bookmarked event citations plus scenario-specific observed facts; contradictory claims cap the score. |
| Same core timings across all alerts | Deterministic family-specific timing profiles and seeded jitter create varied causal sequences; final corpus check found 598 core signatures / 600 alerts. |
| Invalid executable command combinations | Executable-specific templates are used (PowerShell `-File`, MSI `/i`, rundll32 DLL entry, wscript JS, RDP/WinRM/WMI/SMB-specific commands). |
| Process and downloaded/non-EXE objects reused hashes | Process images, referenced artifacts, email attachments and observed files use separate identities/hashes. |
| Domain search was case-sensitive in some paths | IOC and query paths normalize domains and use case-insensitive correlation; defanged `[.]` input is normalized too. |
| Existing case kept stale handoff / SLA | Handoff refresh syncs summary, verdict, evidence and investigation priority; SLA is recalculated from original case creation and recorded in SLA history. |
| High alert worksheet defaulted to Medium | New/current and retry worksheets inherit alert severity. |
| Linux telemetry appeared on Windows endpoints | Sudo/Linux scenarios use Ubuntu hosts and Linux Audit/PAM sources. |
| RDP evidence randomly used 445/5985 | RDP uses 3389 and records explicit default-listener context; other protocols use their protocol-native ports. |
| Feedback was too generic | Post-submit feedback exposes supporting/qualifying/contradicting record roles, actual observations, interpretations and contradiction flags. |
| No safe retry | New attempts preserve the previous submitted worksheet, evidence, case, actions and score. |
| Weak relationship context | Clickable user → endpoint → process → domain/destination → affected endpoint relationships are backed by source records. |
| Portfolio report friction | Current and archived attempts export GitHub-ready Markdown reports including evidence, SLA history and grading feedback. |
| Learner can get stuck | Three optional progressive hints are available without revealing the verdict. |
