import streamlit as st
import pandas as pd
import plotly.express as px


st.set_page_config(page_title="GRC Risk Analytics | test-app.store", layout="wide")
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
    .stApp {{ background-color: {bg_color}; color: {text_color}; font-family: 'Inter', sans-serif; }}
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
    return pd.read_json("risk_quantification_report.json")

df = load_grc_data()

st.title("Enterprise GRC Risk Analytics")
st.markdown("**Domain:** `test-app.store` | **Scenario:** Multi-Cloud Data Migration (AWS ➔ Azure)")

def calculate_professional_compliance(df):
    if df.empty:
        return 100.0

    severity_weights = {'Critical': 10, 'High': 5, 'Medium': 1, 'Low': 0}
    
    df['is_failing'] = (
        (df['Public'] == True) | 
        (df['Retention'] < 14) | 
        (df['Severity'] == 'Critical')
    )
    
    df['weight'] = df['Severity'].map(severity_weights)
    total_possible_weight = df['weight'].sum()
    
    total_deductions = df[df['is_failing'] == True]['weight'].sum()
    
    score = max(0, 100 - (total_deductions / total_possible_weight * 100))
    return score

comp_score = calculate_professional_compliance(df)
kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
kpi1.metric("Total Risk (ALE)", f"${df['ALE'].sum():,.0f}")
kpi2.metric("Avg. Retention", f"{df['Retention'].mean():.1f}d")
kpi3.metric("Critical Assets", len(df[df['Severity'] == 'Critical']))
kpi4.metric("High Sensitivity", len(df[df['Class'] == 'Highly Sensitive']))
kpi5.metric("Compliance Score", f"{comp_score:.1f}%", delta=f"{comp_score - 80:.1f}% vs Target")

st.divider()

col_a, col_b = st.columns(2)

with col_a:
    st.subheader("ALE (Annualized Loss Exposure $) by Resource (Pareto Analysis)")
    fig_bar = px.bar(df.sort_values('ALE', ascending=False), 
                     x='Resource', y='ALE', color='Severity',
                     color_discrete_map={'Critical':'#DC2626', 'High':'#F59E0B', 'Medium':'#3B82F6'},
                     template="plotly_white")
    st.plotly_chart(fig_bar, use_container_width=True)

with col_b:
    st.subheader("Data Sensitivity Composition")
    fig_sun = px.sunburst(df, path=['Class', 'Severity'], values='ALE',
                          color='ALE', color_continuous_scale='Reds')
    st.plotly_chart(fig_sun, use_container_width=True)

st.divider()

col_c, col_d = st.columns(2)

with col_c:
    st.subheader("Risk Heatmap: Severity vs. Sensitivity")
    z_data = df.pivot_table(index='Severity', columns='Class', values='ALE', aggfunc='mean').fillna(0)
    fig_heat = px.imshow(z_data, text_auto=True, color_continuous_scale='YlOrRd')
    st.plotly_chart(fig_heat, use_container_width=True)

with col_d:
    st.subheader("Forensic Readiness (Retention vs. ALE(Annualized Loss Exposure $))")
    fig_bubble = px.scatter(df, x="Retention", y="ALE", size="ALE", color="Public",
                            hover_name="Resource", size_max=40,
                            labels={"Public": "Publicly Exposed"},
                            color_discrete_map={True: '#EF4444', False: '#10B981'})
    st.plotly_chart(fig_bubble, use_container_width=True)

st.divider()

col_e, col_f = st.columns(2)

with col_e:
    st.subheader("Resilience Status (Soft Delete)")
    fig_pie = px.pie(df, names='Public', title="Public Exposure Impact",
                     color='Public', color_discrete_map={True: '#EF4444', False: '#3B82F6'},
                     hole=0.5)
    st.plotly_chart(fig_pie, use_container_width=True)

with col_f:
    st.subheader("Cumulative Risk Curve")
    #Lorenz Curve style:This Style shows how much risk is concentrated among top resources
    df_sorted = df.sort_values('ALE', ascending=False).reset_index()
    df_sorted['Cumulative_Risk'] = df_sorted['ALE'].cumsum() / df_sorted['ALE'].sum() * 100
    fig_line = px.line(df_sorted, x=df_sorted.index, y='Cumulative_Risk', 
                       title="Risk Concentration Index",
                       labels={'index': 'Number of Assets', 'Cumulative_Risk': '% of Total ALE (Annualized Loss Exposure $)'})
    st.plotly_chart(fig_line, use_container_width=True)

st.subheader("Detailed Compliance Audit Log")
st.dataframe(df.style.background_gradient(subset=['ALE'], cmap='Reds'), use_container_width=True)