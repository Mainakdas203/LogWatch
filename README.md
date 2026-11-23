# LogWatch — Security Log Monitoring and Analysis

LogWatch is a beginner-friendly Python project for reviewing normalized security events. Upload a CSV or TXT log, inspect login activity and rule-based alerts, explore interactive charts, and export an event-level incident report.

> **Learning project:** A rule match is a reason to investigate, not proof of an attack. LogWatch does not scan systems, contact outside services, or block IP addresses.

## Features

- Upload CSV and TXT security logs.
- Validate timestamps and IPv4 addresses and report rejected rows.
- Normalize common event labels such as `LOGIN_FAILED` and `LOGIN_SUCCESS`.
- Flag repeated failed logins from one IP within a rolling time window.
- Display total events, failed and successful logins, flagged events, IP counts, and severity.
- Explore severity, timeline, and source-IP charts using Plotly.
- Download the analyzed events, including flags and severity, as a CSV report.
- Use the included synthetic sample log for a safe demonstration; no API key or external LLM is needed.

## Detection logic

The brute-force indicator triggers when **5 or more failed logins from one IP occur within any rolling 10-minute window**. The threshold and window are defined in `logwatch.py`. Events associated with an IP that meets the rule are highlighted for review. Shared networks, user mistakes, and test traffic can trigger the rule; slower or distributed attempts can evade it. An alert does not establish who generated the events or their intent.

Severity labels are illustrative event-name mappings for this learning project, not a formal risk score or production SIEM assessment.

## Supported input formats

### CSV
A header row is required. The canonical columns are `timestamp`, `ip`, and `event`; `details` is optional. Common aliases such as `datetime`, `source_ip`, `event_type`, and `message` are also recognized.

```csv
timestamp,ip,event,details
2026-11-23 08:05:44,192.168.1.15,LOGIN_FAILED,Incorrect password
2026-11-23 08:07:20,192.168.1.15,LOGIN_SUCCESS,Login succeeded
```

### TXT
Pipe-delimited records are supported:

```text
2026-11-23 08:05:44 | 192.168.1.15 | LOGIN_FAILED | Incorrect password
```

The earlier whitespace-delimited format remains supported too:

```text
2026-11-23 08:05:44 192.168.1.15 failed_login | user=admin
```

Blank lines and comment lines beginning with `#` are ignored. Invalid data records are rejected and counted. Login labels are normalized to `failed_login` and `successful_login` for analysis.

## Technologies

- Python (developed and verified in the available Python 3.14.6 environment; the code does not require 3.13-only features)
- Pandas and Python regular expressions for parsing and analysis
- Streamlit for the dashboard
- Plotly for interactive charts
- Pytest for unit tests

## Project structure

```text
LogWatch/
├── app.py
├── logwatch.py
├── data/
│   └── sample_security_logs.txt
├── tests/
│   └── test_logwatch.py
├── requirements.txt
├── README.md
├── INTERVIEW_PREP.md
└── .gitignore
```

## Installation on Windows PowerShell

Python 3.13 or newer is suitable. From this project directory:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If the Python launcher does not have 3.13 installed, use an installed version, for example `python -m venv .venv`.

## Run the dashboard

```powershell
.\.venv\Scripts\Activate.ps1
streamlit run app.py
```

Open the local address printed in the terminal. The app starts with the synthetic sample data; use the uploader to analyze another supported file.

## Run the tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

## Demo scenario

The bundled synthetic log contains five failed login events from `192.168.1.20` between 09:02 and 09:06. Open the dashboard, inspect the suspicious-IP summary and charts, then download the CSV report. Treat the flagged activity as an investigation lead and review its surrounding events.

## Limitations and future work

LogWatch supports a deliberately small set of normalized formats, IPv4 only, and naïve timestamps without timezone normalization. Its threshold may create false positives or miss slow and distributed activity. Future improvements could include additional real-world log formats, timezone-aware timestamps, configurable rules, and richer validation. Do not use this prototype as a production SIEM or for automatic response.
