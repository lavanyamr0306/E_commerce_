import pandas as pd
import plotly.express as px

# Load logs
logs = pd.read_csv('synthetic_logs_enhanced.csv', parse_dates=['timestamp'])

# Initialize a list to store detected anomalies
anomaly_list = []

# 1️⃣ High Response Time
threshold_resp = logs['response_time'].mean() + 2 * logs['response_time'].std()
high_resp = logs[logs['response_time'] > threshold_resp].copy()
high_resp['attack_type'] = 'High Response Time'
high_resp['severity'] = high_resp['response_time']  # use actual value as intensity
anomaly_list.append(high_resp)

# 2️⃣ DDoS Detection (high number of requests per IP per minute)
ip_counts = logs.groupby([pd.Grouper(key='timestamp', freq='1Min'), 'ip_address']).size()
ddos_threshold = ip_counts.mean() + 2 * ip_counts.std()
ddos = ip_counts[ip_counts > ddos_threshold].reset_index()
ddos['attack_type'] = 'DDoS'
ddos['severity'] = ddos[0]  # count as severity
ddos = ddos.rename(columns={0:'count'})
anomaly_list.append(ddos)

# 3️⃣ Failed Login Attack
failed_logins = logs[logs['login_status'] == 'failed']
failed_count = failed_logins.groupby([pd.Grouper(key='timestamp', freq='1Min'), 'ip_address']).size()
failed_threshold = failed_count.mean() + 2 * failed_count.std()
login_attack = failed_count[failed_count > failed_threshold].reset_index()
login_attack['attack_type'] = 'Failed Login'
login_attack['severity'] = login_attack[0]
login_attack = login_attack.rename(columns={0:'count'})
anomaly_list.append(login_attack)

# 4️⃣ Abnormal Product Activity (spikes per product)
product_counts = logs.groupby([pd.Grouper(key='timestamp', freq='1Min'), 'product_id']).size()
product_threshold = product_counts.mean() + 2 * product_counts.std()
product_anomaly = product_counts[product_counts > product_threshold].reset_index()
product_anomaly['attack_type'] = 'Product Spike'
product_anomaly['severity'] = product_anomaly[0]
product_anomaly = product_anomaly.rename(columns={0:'count'})
anomaly_list.append(product_anomaly)

# Combine all anomalies
anomalies = pd.concat(anomaly_list, ignore_index=True, sort=False)

# Fill missing columns for uniform plotting
for col in ['timestamp', 'ip_address', 'product_id', 'attack_type', 'severity']:
    if col not in anomalies.columns:
        anomalies[col] = None

# Plot interactive dashboard
fig = px.scatter(
    anomalies,
    x='timestamp',
    y='ip_address',
    color='attack_type',
    size='severity',
    hover_data=['product_id', 'count', 'response_time'],
    title='Anomaly Detection Dashboard - Multiple Attack Types',
    color_discrete_sequence=px.colors.qualitative.Dark24
)

fig.update_layout(
    xaxis_title='Timestamp',
    yaxis_title='IP Address',
    title_x=0.5
)

fig.show()
