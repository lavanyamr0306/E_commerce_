# trending_products.py
import pandas as pd
import plotly.express as px

logs = pd.read_csv('data/simulated_logs.csv', parse_dates=['timestamp'])
product_counts = logs.groupby([pd.Grouper(key='timestamp', freq='1Min'), 'product_id']).size().unstack(fill_value=0)

# Use z-score threshold per product to find spikes (more robust)
spikes = {}
for product in product_counts.columns:
    series = product_counts[product]
    mean = series.mean()
    std = series.std() if series.std() > 0 else 1
    z = (series - mean) / std
    spikes[product] = (z > 3).sum()  # count times z>3

trending_products = pd.Series(spikes).sort_values(ascending=False)
trending_products = trending_products[trending_products > 0]

print("Trending / booming products detected:")
print(trending_products.head(20))

top_trending = trending_products.head(5).index.tolist()
pd.DataFrame({'recommended_products': top_trending}).to_csv('data/recommendations.csv', index=False)
print("✅ Top 5 recommended products saved to data/recommendations.csv")

trending_df = trending_products.reset_index()
trending_df.columns = ['product_id', 'spike_count']

fig = px.bar(trending_df.head(10), x='product_id', y='spike_count', color='spike_count', text='spike_count', title='Top Trending / Booming Products')
fig.update_traces(textposition='outside')
fig.update_layout(yaxis=dict(dtick=1), xaxis=dict(title='Product ID'), yaxis_title="Spike Count", title_x=0.5)
fig.show()
