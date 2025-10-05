# scripts/block_suspicious_ips.py
import os
import pandas as pd
import numpy as np
import plotly.express as px
from tensorflow.keras.models import load_model
import joblib

os.makedirs("data", exist_ok=True)

# -----------------------------
# Load logs & models
# -----------------------------
logs = pd.read_csv("data/simulated_logs.csv", parse_dates=["timestamp"])

# Load pre-trained models and scaler
scaler = joblib.load("models/scaler.save")
autoencoder = load_model("models/autoencoder_full.h5")
lstm_ae = load_model("models/lstm_ae_full.h5")

# Ensure expected columns (add if missing)
for c in ['failed_logins', 'total_requests', 'avg_response_time', 'mass_clicks', 'sql_flag', 'anomaly_type']:
    if c not in logs.columns:
        logs[c] = 0

# -----------------------------
# Feature engineering per-row
# -----------------------------
# Basic aggregations per ip (for event signals)
ip_agg = logs.groupby('ip_address').agg(
    total_requests=('event_type','count'),
    failed_logins=('login_status', lambda x: (x == 'failed').sum()),
    avg_response_time=('response_time','mean'),
    mass_clicks=('event_type', lambda x: (x=='click').sum()),
)
ip_agg.reset_index(inplace=True)

# Join these back to logs (so each row gets ip-agg signals)
logs = logs.merge(ip_agg, on='ip_address', how='left', suffixes=('','_ipagg'))

# Prepare features used by autoencoder (example: response_time, total_requests, failed_logins)
features = ['response_time', 'total_requests', 'failed_logins', 'mass_clicks', 'avg_response_time']
for f in features:
    if f not in logs.columns:
        logs[f] = 0

X = logs[features].fillna(0).values
X_scaled = scaler.transform(X)

# AE predict
recon = autoencoder.predict(X_scaled, verbose=0)
ae_mse = np.mean(np.power(X_scaled - recon, 2), axis=1)

# Build sequences for LSTM AE per ip (sliding window of event_count)
# For simplicity, we'll compute a rolling window reconstruction error per ip using counts
# Create per-ip time-ordered feature sequences (per-minute aggregation)
logs['minute'] = logs['timestamp'].dt.floor('T')
per_min = logs.groupby(['ip_address','minute']).agg(
    reqs=('event_type','count'),
    failed_logins=('login_status', lambda x: (x=='failed').sum()),
    mean_rt=('response_time','mean')
).reset_index()

# build sequences of 5 minutes per ip
seq_len = 5
lstm_mse_series = []
ip_to_indices = {}  # map original row index -> lstm_mse (approx by minute)
for ip, group in per_min.groupby('ip_address'):
    group = group.sort_values('minute')
    arr = group[['reqs','failed_logins','mean_rt']].fillna(0).values
    if len(arr) >= seq_len:
        seqs = []
        for i in range(len(arr) - seq_len + 1):
            seqs.append(arr[i:i+seq_len])
        seqs = np.array(seqs)
        # scale using scaler (approx: pad or use same scaler)
        # We'll min-max scale per ip to keep values comparable
        from sklearn.preprocessing import MinMaxScaler
        local_scaler = MinMaxScaler()
        try:
            seqs_reshaped = seqs.reshape(-1, seqs.shape[-1])
            seqs_scaled = local_scaler.fit_transform(seqs_reshaped).reshape(seqs.shape)
            pred = lstm_ae.predict(seqs_scaled, verbose=0)
            mse_seq = np.mean(np.power(seqs_scaled - pred, 2), axis=(1,2))
            # map mse back to minutes: assign each minute (end of window) that mse
            for idx, mse in enumerate(mse_seq):
                minute_idx = group.iloc[idx + seq_len - 1]['minute']
                lstm_mse_series.append({'ip_address': ip, 'minute': minute_idx, 'lstm_mse': mse})
        except Exception:
            pass

lstm_mse_df = pd.DataFrame(lstm_mse_series)
# Merge lstm_mse back to logs by ip and minute (approx)
logs = logs.merge(lstm_mse_df, left_on=['ip_address','minute'], right_on=['ip_address','minute'], how='left')
logs['lstm_mse'] = logs['lstm_mse'].fillna(0)

# -----------------------------
# Composite score & classification
# -----------------------------
# normalize AE and LSTM here
ae_norm = (ae_mse - ae_mse.min()) / (ae_mse.ptp() + 1e-9)
lstm_norm = (logs['lstm_mse'] - logs['lstm_mse'].min()) / (logs['lstm_mse'].ptp() + 1e-9)

logs['ae_mse'] = ae_mse
logs['ae_norm'] = ae_norm
logs['lstm_norm'] = lstm_norm

# event_norm
evt = (logs['failed_logins'] / (logs['failed_logins'].max() + 1e-9)) * 0.6 + (logs['total_requests'] / (logs['total_requests'].max() + 1e-9)) * 0.6 + (logs['response_time'] / (logs['response_time'].max() + 1e-9)) * 0.5
evt_norm = (evt - evt.min()) / (evt.ptp() + 1e-9)
logs['event_norm'] = evt_norm

logs['composite_score'] = 0.5 * logs['ae_norm'] + 0.3 * logs['lstm_norm'] + 0.2 * logs['event_norm']

# classify anomaly (expanded)
def classify(row):
    tr = row['total_requests']
    rt = row['response_time']
    fl = row['failed_logins']
    sql_flag = 1 if any(["'" in str(row.get('product_id','')) or "drop table" in str(row.get('product_id','')).lower()]) else 0
    if tr > 50 or 'ddos' in str(row.get('anomaly_type','')).lower():
        return "DDoS Attack", "Rate-limit / Block IP"
    if rt > 3.0:
        return "High Response Time", "Investigate servers / slow endpoints"
    if fl >= 5:
        return "Brute Force Login", "Block IP & enforce 2FA"
    if sql_flag > 0:
        return "SQL Injection Attempt", "Sanitize inputs & block payloads"
    if row['composite_score'] > 0.6 and fl > 0:
        return "Account Takeover Attempt", "Force password reset"
    if row['composite_score'] > 0.7:
        return "Suspicious Behavior", "Monitor & escalate"
    return None, None

logs[['anomaly_name','recommendation']] = logs.apply(classify, axis=1, result_type="expand")

# intensity multiplier mapping
intensity_multiplier = {
    "DDoS Attack": 1.3,
    "High Response Time": 1.0,
    "Brute Force Login": 0.9,
    "SQL Injection Attempt": 1.4,
    "Data Exfiltration": 1.5,
    "Privilege Escalation": 1.6,
    "Mass Clicks / Bot": 0.8,
    "IP Abuse": 1.0,
    "Suspicious Behavior": 0.6,
    None: 0.0
}

comp_norm = (logs['composite_score'] - logs['composite_score'].min()) / (logs['composite_score'].ptp() + 1e-9)
logs['intensity'] = logs['anomaly_name'].map(intensity_multiplier).fillna(0) * comp_norm
logs['is_anomaly'] = logs['anomaly_name'].notnull()

# -----------------------------
# Aggregate report by IP
# -----------------------------
report = (
    logs[logs['is_anomaly']]
    .groupby('ip_address')
    .agg(
        anomaly_name = ('anomaly_name', lambda x: x.mode()[0] if not x.mode().empty else x.iloc[0]),
        recommendation = ('recommendation', lambda x: x.mode()[0] if not x.mode().empty else x.iloc[0]),
        count = ('anomaly_name', 'count'),
        avg_intensity = ('intensity', 'mean')
    ).reset_index()
)

output_path = "data/anomaly_classification_report.csv"
report.to_csv(output_path, index=False)
print(f"\n✅ Anomaly classification report saved to: {os.path.abspath(output_path)}")
print(report.head())

# -----------------------------
# Visualization: bubble chart (timestamp vs composite_score) with intensity size
# -----------------------------
if logs[logs['is_anomaly']].shape[0] > 0:
    fig = px.scatter(
        logs[logs['is_anomaly']],
        x="timestamp",
        y="composite_score",
        color="anomaly_name",
        size="intensity",
        hover_data=["ip_address","event_type","recommendation","intensity"],
        title="Anomalies Over Time — intensity varies by attack type",
        labels={"composite_score":"Composite Anomaly Score"}
    )
    fig.show()
