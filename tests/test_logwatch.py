import io
import pandas as pd
from logwatch import analyze_logs, classify_severity, load_logs, parse_txt_line

def test_txt_parser_and_bad_ip():
    assert parse_txt_line('2026-11-23 09:00:00 10.0.0.1 failed_login')['event'] == 'failed_login'
    assert parse_txt_line('2026-11-23 09:00:00 300.0.0.1 failed_login') is None

def test_txt_rejected_rows():
    rows, rejected = load_logs(io.BytesIO(b'2026-11-23 09:00:00 10.0.0.1 failed_login\ninvalid\n'), 'x.txt')
    assert len(rows) == 1 and rejected == 1

def test_five_failures_flagged_in_window():
    frame = pd.DataFrame([{'timestamp': f'2026-11-23 09:0{i}:00', 'ip': '10.0.0.1', 'event': 'failed_login'} for i in range(5)])
    result = analyze_logs(frame)
    assert result['summary']['flagged_events'] == 5
    assert result['suspicious_ips'].iloc[0]['ip'] == '10.0.0.1'

def test_severity_mapping():
    assert classify_severity('failed_login') == 'Medium'
    assert classify_severity('failed_login', True) == 'Critical'
    assert classify_severity('successful_login') == 'Low'

def test_csv_invalid_rows_counted():
    data = b'timestamp,ip,event\n2026-11-23 09:00:00,10.0.0.1,failed_login\nbad,999.0.0.1,failed_login\n'
    rows, rejected = load_logs(io.BytesIO(data), 'x.csv')
    assert len(rows) == 1 and rejected == 1

def test_pipe_delimited_txt_normalizes_login_events_and_ignores_comment():
    content = b'# sample format\n2026-11-23 08:05:44 | 192.168.1.15 | LOGIN_FAILED | Incorrect password\n2026-11-23 08:07:20 | 192.168.1.15 | LOGIN_SUCCESS | Login succeeded\n'
    rows, rejected = load_logs(io.BytesIO(content), 'sample.txt')
    assert rejected == 0
    assert rows['event'].tolist() == ['failed_login', 'successful_login']
    assert rows['ip'].tolist() == ['192.168.1.15', '192.168.1.15']

def test_csv_login_labels_and_common_column_aliases():
    content = b'datetime,source_ip,event_type,message\n2026-11-23 08:00:00,10.0.0.1,LOGIN_FAILED,bad password\n2026-11-23 08:01:00,10.0.0.1,LOGIN_SUCCESS,logged in\n'
    rows, rejected = load_logs(io.BytesIO(content), 'sample.csv')
    assert rejected == 0
    assert rows['event'].tolist() == ['failed_login', 'successful_login']
    assert rows['details'].tolist() == ['bad password', 'logged in']

def test_five_uppercase_login_failed_events_trigger_rule():
    content = ('timestamp,ip,event\n' + ''.join(f'2026-11-23 08:0{i}:00,10.0.0.2,LOGIN_FAILED\n' for i in range(5))).encode()
    rows, rejected = load_logs(io.BytesIO(content), 'sample.csv')
    result = analyze_logs(rows)
    assert rejected == 0
    assert result['summary']['failed_logins'] == 5
    assert result['summary']['flagged_events'] == 5
    assert result['suspicious_ips'].iloc[0]['ip'] == '10.0.0.2'
