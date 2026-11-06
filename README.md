# LogLens

A local-first security log investigation web app. Serve `dist/` using any static web server; for example, run `python3 -m http.server 8917 --directory dist` and open http://localhost:8917.

## Implemented

- Content-detected OpenSSH, JSON Lines and CSV import; 20 MB limit; explicit missing timestamp context; coverage and rejected-line review.
- Four configurable detection rules, overlapping match merging, original evidence and source locations.
- Structured synthetic scenarios through the same parser and rule engine.
- Overview, time chart, evidence filters, finding details and curated MITRE comparisons.
- Local browser persistence, statuses, notes, investigation groups, deletion, JSON and printable HTML exports with optional redaction.

This implementation uses browser JavaScript and local storage instead of the suggested Python/Streamlit/SQLite stack. Logs never leave the browser. Browser storage is device-local, subject to quota and browser clearing, and is not encrypted by this app. Export investigations for archival. The private hosted application does not provide shared multi-user case storage.

## Event schema

One JSON object per physical line, or CSV with headers:

`timestamp,action,outcome,username,source_ip,hostname`

Timestamp must be ISO 8601; provide the import UTC offset for naive timestamps. `action` must be `login` or `invalid_user`; `outcome` must be `success` or `failure`. `timestamp_utc` and `event_type` are accepted aliases. Optional source_port. Unknown identity fields remain null and exclude events from rules requiring those fields. CSV supports quoted commas and doubled quotes, but not multiline fields.

OpenSSH supports Failed password, Accepted password, Accepted publickey, and Invalid user messages with ISO or traditional syslog prefixes. Traditional syslog needs year and fixed UTC offset; split multi-year and daylight-saving-transition files before import. Unsupported messages are retained in the import report. Exact repeated physical lines are excluded and counted; semantically similar but different lines remain separate.

## Validation

`node --test tests/engine.test.js` exercises thresholds, merging, correlation, time windows, parsing, duplicates and samples. `node --check dist/app.js` checks interface syntax.

## Limitations

Configured pattern matches are review cues, not proof of compromise or attribution. ATT&CK references are curated mappings versioned 2026-09-24, not live enrichment. Invalid-user mapping to password guessing is contextual. A standalone invalid-user message and a subsequent failed-password message can be separate log records for the same connection; counts describe records, not unique sessions. No continuous monitoring or reputation lookups. Large imports may be constrained by browser memory/storage. Redacted exports omit raw lines, analyst notes, groups and identity fields. HTML exports can be printed using the browser's print command.

## Expanded demos (v1.1)

The demo selector now offers 13 scenarios: normal logins, mixed authentication, password guessing, multi-account failures, success after failures, invalid users, distributed HTTP bursts, single-source HTTP bursts, missing-path scanning, SQL injection-like strings, traversal-like strings, server errors, and combined incidents. Generated request strings are inert log text; no attack traffic is sent.

Run again creates fresh records for the current scenario and analyzes them with the current rule settings. Reset demo clears demo data and returns to the start screen. Changes to notes/status/groups prompt before replacement. Demo storage (`loglens-demo-v2`) is separate from uploaded investigation storage (`loglens-v1`); resetting demos preserves an uploaded investigation. Delete saved data removes both.

Structured HTTP events use action `http_request`, ISO timestamp, hostname, source_ip, path beginning with `/`, and integer status_code 100–599. Outcome is `failure` for 400–599 and `success` otherwise. Username is optional. CSV supports these same column names. Raw Nginx/Apache formats and packet/network flow data remain unsupported.

Six HTTP rules add distributed bursts (100 requests from at least 10 IPs in 1 minute), single-source bursts (60 requests in 1 minute), at least 10 distinct 404 paths in 5 minutes, at least 3 narrow SQL/traversal pattern matches in 5 minutes, and at least 20 server errors in 5 minutes. Counts and windows are configurable; distributed detection also has a fixed minimum of 10 source IPs. DDoS-like demos are application-layer illustrations, not proof of denial of service or coverage of all DDoS variants. Server errors are operational findings with no attack attribution. UI metrics count all successful/failed events and the event explorer includes event type, HTTP status and path.
