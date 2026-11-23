from pathlib import Path
import pandas as pd
import plotly.express as px
import streamlit as st
from logwatch import analyze_logs, load_logs

st.set_page_config(page_title='LogWatch', page_icon='🛡️', layout='wide')
st.title('🛡️ LogWatch')
st.caption('Security log monitoring and analysis — transparent rules for learning, not a production SIEM.')
st.info('A flagged IP is an investigation lead, not proof of a malicious actor. No network activity or automatic blocking is performed.')
sample = Path(__file__).parent / 'data' / 'sample_security_logs.txt'
upload = st.file_uploader('Upload a CSV or TXT security log', type=['csv', 'txt'])
try:
    if upload:
        events, rejected = load_logs(upload, upload.name)
    else:
        st.caption('Showing synthetic demonstration logs. Upload a supported file to analyze it.')
        with sample.open('rb') as handle:
            events, rejected = load_logs(handle, sample.name)
except (ValueError, UnicodeDecodeError, pd.errors.ParserError) as exc:
    st.error(f'Could not read this file: {exc}')
    st.stop()
if events.empty:
    st.warning('No valid log entries were found.')
    st.write(f'Rejected rows: {rejected}')
    st.stop()
result = analyze_logs(events)
s = result['summary']
cols = st.columns(5)
for col, label, value in zip(cols, ['Total events', 'Failed logins', 'Successful logins', 'Flagged events', 'Rejected rows'], [s['total_events'], s['failed_logins'], s['successful_logins'], s['flagged_events'], rejected]):
    col.metric(label, value)
st.subheader('Investigation summary')
if result['suspicious_ips'].empty:
    st.write('No IP met the configured failed-login threshold in this dataset.')
else:
    for _, row in result['suspicious_ips'].iterrows():
        st.write(f"**{row['ip']}** — {row['failed_logins']} failed logins and {row['event_count']} total events. Review context before drawing conclusions.")
st.caption('Rule: at least 5 failed logins from one IP within any rolling 10-minute window. See logwatch.py.')
left, right = st.columns(2)
with left:
    counts = result['events'].groupby('severity').size().reindex(['Low', 'Medium', 'High', 'Critical'], fill_value=0).rename('events').reset_index()
    st.plotly_chart(px.bar(counts, x='severity', y='events', color='severity', title='Events by severity'), use_container_width=True)
with right:
    timeline = result['events'].set_index('timestamp').resample('5min').size().rename('events').reset_index()
    st.plotly_chart(px.line(timeline, x='timestamp', y='events', markers=True, title='Event volume (5-minute buckets)'), use_container_width=True)
by_ip = result['events'].groupby('ip').agg(event_count=('event', 'size'), failed_logins=('failed_login', 'sum')).reset_index().sort_values('event_count', ascending=False)
st.plotly_chart(px.bar(by_ip, x='ip', y=['failed_logins', 'event_count'], barmode='group', title='Source IP activity'), use_container_width=True)
st.subheader('Analyzed events')
st.dataframe(result['events'], use_container_width=True, hide_index=True)
st.download_button('Download detailed incident report (CSV)', result['events'].to_csv(index=False).encode('utf-8'), file_name='logwatch_incident_report.csv', mime='text/csv')
