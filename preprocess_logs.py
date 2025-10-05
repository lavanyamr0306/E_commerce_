# data/preprocess_resample.py
import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler
import os

os.makedirs("data", exist_ok=True)

df = pd.read_csv('data/simulated_logs.csv', parse_dates=['timestamp'])
df.set_index('timestamp', inplace=True)

# Resample per minute
agg_df = df.resample('1Min').agg({
    'user_id': pd.Series.nunique,
    'product_id': 'count',
    'response_time': ['mean','max']
})
agg_df.columns = ['unique_users','total_events','mean_response','max_response']

# Count event types per minute
event_counts = df.groupby([pd.Grouper(freq='1Min'),'event_type']).size().unstack(fill_value=0)
agg_df = agg_df.join(event_counts, how='left').fillna(0)

# Create explicit signals
agg_df['failed_logins'] = df.groupby(pd.Grouper(freq='1Min'))['login_status'].apply(lambda x: (x=='failed').sum()).reindex(agg_df.index, fill_value=0)
agg_df['total_requests'] = agg_df['total_events']
agg_df['avg_response_time'] = agg_df['mean_response']
agg_df['mass_clicks'] = agg_df.get('click', 0)
# SQL flag: crude detection if product_id contains suspicious payloads (this requires original logs scattering)
# We'll create a simple per-minute flag by searching raw logs
raw = df.reset_index()
raw['minute'] = raw['timestamp'].dt.floor('T')
raw['sql_flag'] = raw['product_id'].astype(str).str.contains("(' OR|; DROP|--|SELECT|UNION|OR 1=1)", case=False, regex=True).astype(int)
sql_per_min = raw.groupby('minute')['sql_flag'].sum()
agg_df['sql_flag'] = sql_per_min.reindex(agg_df.index, fill_value=0)

# More features can be added here...

# Fill NaNs
agg_df.fillna(0, inplace=True)

# Normalize and save
scaler = MinMaxScaler()
scaled = scaler.fit_transform(agg_df)
scaled_df = pd.DataFrame(scaled, columns=agg_df.columns, index=agg_df.index)

scaled_df.to_csv('data/preprocessed_logs.csv')
import joblib
joblib.dump(scaler, "models/scaler_preprocess.save")
print("✅ Preprocessing complete! Saved preprocessed_logs.csv in data/ and scaler_preprocess.save")
