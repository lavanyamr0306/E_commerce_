import pandas as pd
import plotly.express as px

# -----------------------------
# Load enhanced synthetic logs
# -----------------------------
df = pd.read_csv(
    "C:/Users/lavan/OneDrive/Desktop/EcommerceProject/synthetic_logs_enhanced.csv",
    parse_dates=['timestamp']
)

# -----------------------------
# Filter only anomalies
# -----------------------------
anomalies = df[df['anomaly_type'] != 'normal']

# -----------------------------
# Aggregate anomaly counts per type
# -----------------------------
anomaly_counts = anomalies.groupby('anomaly_type').size().reset_index(name='count')

# Normalize counts for intensity (for color scaling)
anomaly_counts['intensity'] = (anomaly_counts['count'] - anomaly_counts['count'].min()) / \
                              (anomaly_counts['count'].max() - anomaly_counts['count'].min() + 1e-9)

print("Anomaly counts and normalized intensity:")
print(anomaly_counts)

# -----------------------------
# Bar chart: Summary of all anomalies
# -----------------------------
fig_bar = px.bar(
    anomaly_counts,
    x='anomaly_type',
    y='count',
    color='intensity',
    text='count',
    title='Anomaly Detection Summary',
    color_continuous_scale='Viridis',
    labels={'anomaly_type': 'Anomaly Type', 'count': 'Number of Events'}
)

fig_bar.update_traces(textposition='outside')
fig_bar.update_layout(
    yaxis=dict(dtick=1),
    xaxis=dict(title='Anomaly Type'),
    yaxis_title="Event Count",
    title_x=0.5
)

fig_bar.show()

# -----------------------------
# Scatter plot: Anomalies over time
# -----------------------------
# Optional: size points by response_time if numeric
size_col = 'response_time' if 'response_time' in anomalies.columns else None

fig_scatter = px.scatter(
    anomalies,
    x='timestamp',
    y='anomaly_type',
    color='anomaly_type',
    size=size_col,
    title='Anomalies Over Time',
    hover_data=['user_id', 'ip_address', 'device_type', 'response_time']
)

fig_scatter.update_layout(
    yaxis_title="Anomaly Type",
    xaxis_title="Timestamp",
    title_x=0.5
)

fig_scatter.show()

# -----------------------------
# Save anomaly summary for dashboard
# -----------------------------
anomaly_counts.to_csv('data/anomaly_summary.csv', index=False)
print("✅ Anomaly summary saved to data/anomaly_summary.csv")
