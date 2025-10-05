# data_generator.py
import pandas as pd
import random
from datetime import datetime, timedelta
import os

os.makedirs("data", exist_ok=True)

NUM_ROWS = 5000
NUM_ANOMALY_USERS = 20
ANOMALIES_PER_USER = (2, 6)

REGIONS = ['North', 'South', 'East', 'West']
DEVICE_TYPES = ['Mobile', 'Desktop', 'Tablet']
EVENT_TYPES = ['view', 'click', 'purchase', 'login', 'download']
PRODUCT_IDS = [f'P{i:03d}' for i in range(1, 201)]
USER_IDS = [f'U{i:04d}' for i in range(1, 401)]

def generate_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

data = []
start_time = datetime.now() - timedelta(days=7)

# normal logs
for _ in range(NUM_ROWS):
    timestamp = start_time + timedelta(minutes=random.randint(0, 7*24*60))
    user_id = random.choice(USER_IDS)
    ip_address = generate_ip()
    region = random.choice(REGIONS)
    device_type = random.choice(DEVICE_TYPES)
    product_id = random.choice(PRODUCT_IDS)
    event_type = random.choices(EVENT_TYPES, weights=[50,30,10,5,5])[0]
    login_status = random.choice(['success','failed']) if event_type=='login' else 'success'
    response_time = round(random.uniform(0.1,2.0),2)
    data.append([timestamp, user_id, ip_address, region, device_type, product_id, event_type, login_status, response_time, 'normal'])

# anomalies
anomaly_types = ['high_response','failed_login','mass_clicks','ip_abuse','ddos','sql_injection','data_exfil','intrusion','config_change']
for i, user in enumerate(USER_IDS[:NUM_ANOMALY_USERS]):
    for _ in range(random.randint(*ANOMALIES_PER_USER)):
        timestamp = start_time + timedelta(minutes=random.randint(0, 7*24*60))
        ip_address = generate_ip()
        region = random.choice(REGIONS)
        device_type = random.choice(DEVICE_TYPES)
        product_id = random.choice(PRODUCT_IDS)
        anomaly_type = random.choice(anomaly_types)

        event_type = random.choice(EVENT_TYPES)
        login_status = 'success'
        response_time = round(random.uniform(0.1,2.0),2)

        if anomaly_type == 'high_response':
            response_time = round(random.uniform(5.0,12.0),2)
        elif anomaly_type == 'failed_login':
            event_type = 'login'
            login_status = 'failed'
            ip_address = generate_ip()
        elif anomaly_type == 'mass_clicks':
            event_type = 'click'
        elif anomaly_type == 'ip_abuse':
            ip_address = '192.168.0.100'
        elif anomaly_type == 'ddos':
            ip_address = '203.0.113.1'
            # many quick events
            for _ in range(random.randint(20,45)):
                ts = timestamp + timedelta(seconds=random.randint(0,60))
                data.append([ts, user, ip_address, region, device_type, product_id, 'view', 'success', round(random.uniform(0.1,1.0),2), 'ddos'])
            continue
        elif anomaly_type == 'sql_injection':
            product_id = random.choice(["P001","P002","'; DROP TABLE logs;--", "' OR '1'='1"])
            event_type = 'purchase'
        elif anomaly_type == 'data_exfil':
            event_type = 'download'
        elif anomaly_type == 'intrusion':
            event_type = 'login'
            login_status = 'failed'
            ip_address = generate_ip()
        elif anomaly_type == 'config_change':
            event_type = 'purchase'

        data.append([timestamp, user, ip_address, region, device_type, product_id, event_type, login_status, response_time, anomaly_type])

df = pd.DataFrame(data, columns=[
    'timestamp','user_id','ip_address','region','device_type','product_id',
    'event_type','login_status','response_time','anomaly_type'
])
df = df.sample(frac=1, random_state=42).reset_index(drop=True)
df.to_csv('data/simulated_logs.csv', index=False)
print("✅ Enhanced synthetic logs generated: data/simulated_logs.csv")
