# Sentinel Desk v3 — release verification

This release hardens the SOC lab issues found during review: concurrent bookmark persistence, anti-gaming grading, scenario/timeline variety, executable-specific command evidence, separate object hashes, normalized IOC lookup, case handoff/SLA synchronization, alert-severity inheritance, Linux/RDP consistency, retry history, relationship evidence, Markdown case reporting and optional hints.

## Source-level quality check performed for this delivery

A dependency-free check was executed directly against the final v3 scenario generator and scoring modules for all 600 baseline scenarios. It produced:

- 600 unique `ALT3-` scenarios and 14,441 correlated records.
- 598 unique core process/DNS/network timing signatures across the 600 scenarios (the old fixed five-offset pattern is gone).
- 13 RDP scenarios checked at port 3389 with explicit default-listener context.
- 58 Linux Audit/PAM records checked; all are attached to Ubuntu endpoints.
- 82 `msiexec.exe` command records checked; `-File` is never used with `msiexec` and MSI paths use `/i ... /qn` syntax.
- 0 process-image ↔ file/attachment hash collisions across the corpus.
- IOC normalization check: uppercase and defanged `.test` domains normalize to the same canonical domain.
- Reference evidence-based worksheet: 100/100.
- Generic filler worksheet using the correct verdict, source visits, bookmarks and cited IDs: 58/100, not 100/100.

The final source also includes an expanded API acceptance/regression suite in `tests/`. Because this delivery environment could not download the npm dependency tree, the full dependency-backed `npm run test:acceptance`, TypeScript project check and production build were not re-run here after the final edits. Run `VERIFY_FINAL.bat` on Windows after dependencies are available to execute all three against the exact delivered source.

## Database migration

`drizzle/0002_atomic_bookmarks.sql` adds `investigation_bookmarks`, keyed by analyst + alert + attempt + event. Existing JSON bookmarks are lazily copied into this table when an investigation is opened, so an existing local workspace can be upgraded without deleting earlier investigation history.

## Local data

The ZIP does not contain personal investigation state. Local progress is stored in `.wrangler/state`. If upgrading an existing installation and you want to preserve progress, retain that folder while replacing the source files and then run the new launcher/migrations.
