# LogWatch Interview Preparation

## Simple explanation
LogWatch accepts normalized CSV or simple TXT security logs, validates entries, applies a transparent failed-login rule, assigns simple severity labels, and presents an interactive dashboard and downloadable report. It is a learning tool: an alert means investigate, not that an attack is confirmed.

## Architecture and workflow
1. `app.py` chooses uploaded or synthetic logs and renders the dashboard.
2. `load_logs` parses CSV/TXT, normalizes fields, validates rows, and counts rejected data.
3. `analyze_logs` derives login indicators, runs the per-IP rolling-window rule, assigns severity, and calculates summaries.
4. Streamlit presents metrics, suspicious IPs, Plotly charts, a table, and a CSV report download.

## Major functions
- `parse_txt_line(line)`: regex extracts timestamp, IPv4, event and optional details. Bad structure/date/address returns `None`.
- `_valid_ip(ip)`: checks four numeric IPv4 octets in the 0–255 range.
- `load_logs(file_obj, filename)`: reads required CSV fields or supported TXT lines and returns `(valid_events, rejected_count)`.
- `classify_severity(event, flagged=False)`: applies the simple event-name mapping. Rule-flagged failures are Critical; selected events High or Medium; others Low.
- `analyze_logs(events)`: adds login booleans, checks sorted failure timestamps per IP, marks qualifying failures, then returns annotated events, suspicious IP summary, and headline counts.
- The main `app.py` flow handles upload errors, charts, event table, and report download.

## Brute-force detection
The rule is at least 5 failed logins from one IP within any rolling 10-minute window. For each source IP, timestamps are sorted and a moving left/right window counts failures. The rule is intentionally visible in `logwatch.py`. NAT/shared addresses and user mistakes may cause false positives; slow attempts or attempts spread across IPs may be missed. The flag does not establish an attack.

## Severity classification
`failed_login` is Medium by default; failures involved in a triggered burst are Critical. `malware_detected`, `privilege_escalation`, and `account_locked` are High. `failed_login`, `firewall_block`, and `suspicious_process` are Medium; other events are Low. These are example priority labels, not a formal risk score.

## 15 likely technical questions and answers
1. **What does the project do?** Parses normalized events, applies a visible rule, and presents investigation summaries and a report.
2. **Why Python?** It is readable and its data/dashboard libraries make a small prototype quick to explain.
3. **What does Pandas provide?** Tabular event storage plus parsing, filtering, grouping, and summaries.
4. **Where is regex used?** Extracting structured fields from the supported TXT log line.
5. **How does brute-force detection work?** Five failures from one IP in a rolling ten-minute period trigger a review flag.
6. **Why a rolling window?** A total over a whole file could combine attempts from hours apart; a window finds bursts.
7. **Does a flag prove an attack?** No. It is a suspicious pattern requiring context and investigation.
8. **Give a false positive example.** Many users behind one NAT address can generate multiple failures.
9. **Give a false negative example.** Slow attempts or attempts distributed across addresses may avoid this simple threshold.
10. **What happens to invalid rows?** They are excluded and counted for visibility.
11. **How is severity assigned?** A small, documented mapping based on event name and rule flag.
12. **Why Streamlit?** It turns Python analysis into a usable local dashboard with little UI boilerplate.
13. **Why Plotly?** It provides interactive charts for event severity, time, and source-IP activity.
14. **What would you improve next?** Support more real log formats, time zones, configurable thresholds, and broader tests.
15. **Is it production-ready?** No. It is a portfolio prototype with limited formats and illustrative rules, not a SIEM.

## Two-minute project presentation
“I built LogWatch, a small Python security log analysis project to demonstrate how basic rules can support investigation. It accepts normalized CSV or a simple TXT format and includes synthetic data for a safe demo. Pandas holds the events, and regex extracts fields from text lines. I validate timestamps and IPv4 addresses and count invalid rows so data quality is visible.

The main detection rule looks for at least five failed logins from the same IP in any rolling ten-minute window. I sort each IP’s failure times and maintain a moving window. Matching failures are highlighted for review, and a simple event mapping assigns severity. A Streamlit dashboard shows totals, source-IP counts, Plotly charts, event details, and a downloadable CSV report.

A rule trigger is not proof of an attack. Shared networks and user mistakes can cause false positives, and slower or distributed attempts can be missed. This is a learning prototype, not a production SIEM, and it never scans or blocks systems. I would next add more log formats, timezone support, configurable thresholds, and additional validation.”
