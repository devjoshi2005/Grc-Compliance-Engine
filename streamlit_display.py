import streamlit as st
import pandas as pd
import plotly.express as px
import json
from datetime import datetime

st.set_page_config(page_title="GRC Risk Analytics Dashboard", layout="wide")

theme = st.sidebar.radio("Select Dashboard Theme", ["High-Contrast Dark", "Professional Light"])

if theme == "High-Contrast Dark":
    bg_color = "#0E1117"
    card_color = "#161B22"
    text_color = "#E6EDF3"
    chart_template = "plotly_dark"
elif theme == "Professional Light":
    bg_color = "#F8FAFC"
    card_color = "#161B22"
    text_color = "#1E293B"
    chart_template = "plotly_white"

st.markdown(f"""
    <style>
    .stApp {{ background-color: {bg_color}; color: {text_color}; font-family: 'Inter', sans-serif;  }}
    [data-testid="stMetricValue"] {{ color: #3B82F6; font-weight: 700; }}
    div[data-testid="stMetric"] {{ 
        background-color: {card_color}; 
        padding: 15px; 
        border-radius: 10px; 
        border: 1px solid #30363D;
    }}
    </style>
    """, unsafe_allow_html=True)


@st.cache_data
def load_grc_data():
    """Load and preprocess risk quantification data"""
    try:
        with open("risk_quantification_report.json", "r") as f:
            data = json.load(f)
        df = pd.DataFrame(data)
        
        df['is_public'] = df.get('is_public', False)
        df['retention_days'] = df.get('retention_days', 30)
        df['severity'] = df.get('severity', 'Medium')
        df['classification'] = df.get('classification', 'Internal')
        df['soft_delete'] = df.get('soft_delete', True)
        df['is_active'] = df.get('is_active', True)
        df['ale'] = df.get('ale', 0)
        df['asset'] = df.get('asset', 'Unknown')
        
        return df
    except Exception as e:
        st.error(f"Error loading data: {e}")
        return pd.DataFrame()

df = load_grc_data()

if df.empty:
    st.warning("No risk data available. Please run risk_engine.py first.")
    st.stop()

st.title("Enterprise GRC Risk Analytics")
st.markdown("**Domain:** `test-app.store` | **Scenario:** Multi-Cloud Data Migration (AWS ➔ Azure)")

def calculate_compliance_score(df):
    """Calculate compliance score based on risk factors"""
    if df.empty:
        return 100.0
    
    df['is_risky'] = (
        (df['is_public'] == True) | 
        (df['retention_days'] < 14) | 
        (df['severity'] == 'Critical')
    )
    
    total_assets = len(df)
    risky_assets = df['is_risky'].sum()
    
    score = max(0, 100 - (risky_assets / total_assets * 100))
    return round(score, 1)

comp_score = calculate_compliance_score(df)
total_ale = df['ale'].sum()
avg_retention = df['retention_days'].mean()
critical_count = len(df[df['severity'] == 'Critical'])
highly_sensitive_count = len(df[df['classification'] == 'Highly Sensitive'])

kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
kpi1.metric("Total Risk (ALE)", f"${total_ale:,.0f}")
kpi2.metric("Avg. Retention", f"{avg_retention:.1f}d")
kpi3.metric("Critical Findings", f"{critical_count}")
kpi4.metric("High Sensitivity Assets", f"{highly_sensitive_count}")
kpi5.metric("Compliance Score", f"{comp_score:.1f}%", 
           delta=f"{comp_score - 80:.1f}% vs Target")

st.divider()

col_a, col_b = st.columns(2)

with col_a:
    st.subheader("ALE by Resource (Top 20)")
    top_resources = df.nlargest(20, 'ale')
    fig_bar = px.bar(top_resources, 
                     x='asset', y='ale', color='severity',
                     color_discrete_map={
                         'Critical': '#DC2626', 
                         'High': '#F59E0B', 
                         'Medium': '#3B82F6',
                         'Low': '#10B981'
                     },
                     template=chart_template)
    fig_bar.update_xaxes(tickangle=45)
    fig_bar.update_layout(showlegend=True)
    st.plotly_chart(fig_bar, use_container_width=True)

with col_b:
    st.subheader("Data Sensitivity vs Severity Distribution")
    if not df.empty:
        fig_sun = px.sunburst(df, path=['classification', 'severity'], values='ale',
                              color='ale', color_continuous_scale='Reds')
        st.plotly_chart(fig_sun, use_container_width=True)

st.divider()

col_c, col_d = st.columns(2)

with col_c:
    st.subheader("Risk Heatmap: Severity vs Classification")
    z_data = df.pivot_table(index='severity', columns='classification', 
                           values='ale', aggfunc='sum').fillna(0)
    fig_heat = px.imshow(z_data, text_auto=True, color_continuous_scale='YlOrRd',
                         template=chart_template)
    st.plotly_chart(fig_heat, use_container_width=True)

with col_d:
    st.subheader("Forensic Readiness (Retention vs ALE)")
    fig_bubble = px.scatter(df, x="retention_days", y="ale", size="ale", 
                           color="is_public",
                           hover_name="asset", size_max=40,
                           labels={"is_public": "Publicly Exposed"},
                           color_discrete_map={True: '#EF4444', False: '#10B981'},
                           template=chart_template)
    st.plotly_chart(fig_bubble, use_container_width=True)

st.divider()

col_e, col_f = st.columns(2)

with col_e:
    st.subheader("Public Exposure Distribution")
    fig_pie = px.pie(df, names='is_public', title="Public vs Private Assets",
                     color='is_public', 
                     color_discrete_map={True: '#EF4444', False: '#10B981'},
                     hole=0.5,
                     template=chart_template)
    fig_pie.update_traces(textinfo='label+percent')
    st.plotly_chart(fig_pie, use_container_width=True)

with col_f:
    st.subheader("Cumulative Risk Concentration")
    df_sorted = df.sort_values('ale', ascending=False).reset_index(drop=True)
    df_sorted['cumulative_risk_pct'] = df_sorted['ale'].cumsum() / df_sorted['ale'].sum() * 100
    df_sorted['asset_rank'] = df_sorted.index + 1
    
    fig_line = px.line(df_sorted, x='asset_rank', y='cumulative_risk_pct', 
                       title="Lorenz Curve: Risk Concentration",
                       labels={'asset_rank': 'Number of Assets', 
                              'cumulative_risk_pct': '% of Total ALE'},
                       template=chart_template)
    fig_line.add_hline(y=80, line_dash="dash", line_color="red", 
                       annotation_text="Pareto 80% Threshold")
    st.plotly_chart(fig_line, use_container_width=True)

st.subheader("Detailed Risk Register")
st.dataframe(
    df[['asset', 'asset_type', 'service', 'severity', 'classification', 
        'is_public', 'retention_days', 'soft_delete', 'ale', 'control', 
        'compliance']].style.background_gradient(subset=['ale'], cmap='Reds'),
    use_container_width=True,
    height=400
)

st.sidebar.subheader("Quick Filters")
severity_filter = st.sidebar.multiselect(
    "Severity", 
    options=df['severity'].unique(),
    default=df['severity'].unique()
)

classification_filter = st.sidebar.multiselect(
    "Classification",
    options=df['classification'].unique(),
    default=df['classification'].unique()
)

public_filter = st.sidebar.checkbox("Show only public assets", value=False)

if st.sidebar.button("Refresh Data"):
    st.cache_data.clear()
    st.rerun()

st.caption(f"Dashboard generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC")
