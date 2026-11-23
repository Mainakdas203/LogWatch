import re
from datetime import timedelta
import pandas as pd

BRUTE_FORCE_THRESHOLD = 5  # At least five failures in a rolling ten-minute window.
BRUTE_FORCE_WINDOW = timedelta(minutes=10)
LOG_PATTERN = re.compile(r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+(?P<event>[A-Za-z_ -]+?)(?:\s+\|\s*(?P<details>.*))?$")

EVENT_ALIASES = {
    'login_failed': 'failed_login',
    'login_failure': 'failed_login',
    'failed_login': 'failed_login',
    'login_success': 'successful_login',
    'successful_login': 'successful_login',
}
CSV_COLUMN_ALIASES = {
    'timestamp': ('timestamp', 'datetime', 'event_time', 'date_time', 'time', 'date'),
    'ip': ('ip', 'source_ip', 'src_ip', 'client_ip', 'remote_ip', 'src'),
    'event': ('event', 'event_type', 'action', 'activity', 'type'),
    'details': ('details', 'message', 'description', 'info'),
}

def _valid_ip(ip):
    try:
        parts = [int(x) for x in str(ip).split('.')]
        return len(parts) == 4 and all(0 <= x <= 255 for x in parts)
    except ValueError:
        return False

def _normalize_event(event):
    """Convert common login labels to the analyzer's canonical event names."""
    normalized = re.sub(r'[^a-z0-9]+', '_', str(event).strip().lower()).strip('_')
    return EVENT_ALIASES.get(normalized, normalized)

def parse_txt_line(line):
    """Parse pipe-delimited or legacy whitespace-delimited TXT log entries."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    # Supplied format: timestamp | IPv4 | event | free-form details
    if '|' in line:
        fields = [field.strip() for field in line.split('|', maxsplit=3)]
        if len(fields) < 3:
            return None
        timestamp, ip, event = fields[:3]
        details = fields[3] if len(fields) == 4 else ''
    else:
        match = LOG_PATTERN.match(line)
        if not match:
            return None
        row = match.groupdict()
        timestamp, ip, event, details = row['timestamp'], row['ip'], row['event'], row['details'] or ''

    try:
        parsed_timestamp = pd.to_datetime(timestamp, errors='raise')
    except (ValueError, TypeError):
        return None
    if not _valid_ip(ip) or not event.strip():
        return None
    return {'timestamp': parsed_timestamp, 'ip': ip.strip(), 'event': _normalize_event(event), 'details': details.strip()}

def load_logs(file_obj, filename):
    """Return normalized valid event rows and a count of rejected data rows."""
    if filename.lower().endswith('.csv'):
        raw = pd.read_csv(file_obj, encoding='utf-8-sig')
        raw.columns = [re.sub(r'[^a-z0-9]+', '_', str(c).strip().lower()).strip('_') for c in raw.columns]
        rename = {}
        for canonical, aliases in CSV_COLUMN_ALIASES.items():
            if canonical not in raw.columns:
                found = next((alias for alias in aliases if alias in raw.columns), None)
                if found:
                    rename[found] = canonical
        raw = raw.rename(columns=rename)
        missing = {'timestamp', 'ip', 'event'} - set(raw.columns)
        if missing:
            raise ValueError('CSV must contain timestamp, ip, and event columns (common aliases such as source_ip and event_type are also supported).')
        if 'details' not in raw:
            raw['details'] = ''
        raw['timestamp'] = pd.to_datetime(raw['timestamp'], errors='coerce')
        raw['ip'] = raw['ip'].astype('string').str.strip()
        raw['event'] = raw['event'].map(_normalize_event)
        valid = raw['timestamp'].notna() & raw['ip'].map(_valid_ip) & raw['event'].notna() & raw['event'].ne('')
        return raw.loc[valid, ['timestamp', 'ip', 'event', 'details']].reset_index(drop=True), int((~valid).sum())

    text = file_obj.read()
    if isinstance(text, bytes):
        text = text.decode('utf-8-sig')
    rows = []
    rejected = 0
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        row = parse_txt_line(line)
        if row is None:
            rejected += 1
        else:
            rows.append(row)
    return pd.DataFrame(rows, columns=['timestamp', 'ip', 'event', 'details']), rejected

def classify_severity(event, flagged=False):
    """Apply an illustrative and explainable severity mapping."""
    event = _normalize_event(event)
    if flagged:
        return 'Critical'
    if event in {'malware_detected', 'privilege_escalation', 'account_locked'}:
        return 'High'
    if event in {'failed_login', 'firewall_block', 'suspicious_process'}:
        return 'Medium'
    return 'Low'

def analyze_logs(events):
    """Annotate events, find burst failures, and compute summaries."""
    data = events.copy()
    data['timestamp'] = pd.to_datetime(data['timestamp'], errors='coerce')
    data['event'] = data['event'].map(_normalize_event)
    data['failed_login'] = data['event'].eq('failed_login')
    data['successful_login'] = data['event'].eq('successful_login')
    flagged_ips = set()
    for ip, group in data.loc[data['failed_login']].groupby('ip'):
        times = group['timestamp'].dropna().sort_values().tolist()
        left = 0
        for right, current in enumerate(times):
            while current - times[left] > BRUTE_FORCE_WINDOW:
                left += 1
            if right - left + 1 >= BRUTE_FORCE_THRESHOLD:
                flagged_ips.add(ip)
                break
    data['rule_flagged'] = data['ip'].isin(flagged_ips) & data['failed_login']
    data['severity'] = [classify_severity(e, f) for e, f in zip(data['event'], data['rule_flagged'])]
    suspicious = data[data['ip'].isin(flagged_ips)].groupby('ip').agg(failed_logins=('failed_login', 'sum'), event_count=('event', 'size')).reset_index()
    summary = {'total_events': len(data), 'failed_logins': int(data['failed_login'].sum()), 'successful_logins': int(data['successful_login'].sum()), 'flagged_events': int(data['rule_flagged'].sum())}
    return {'events': data.sort_values('timestamp').reset_index(drop=True), 'suspicious_ips': suspicious.sort_values('failed_logins', ascending=False).reset_index(drop=True), 'summary': summary}
