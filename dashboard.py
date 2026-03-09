import streamlit as st
import pandas as pd
import sqlite3
import os

# --- PAGE CONFIG ---
st.set_page_config(
    page_title="Sentinel-AI Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# --- STYLING & CUSTOM CSS ---
st.markdown("""
<style>
    /* Dark Theme Override & Glow Effects */
    body {
        background-color: #0f172a;
        color: #f8fafc;
    }
    .stApp {
        background-color: #0f172a;
    }
    h1 {
        background: linear-gradient(135deg, #fff, #38bdf8);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-shadow: 0 0 20px rgba(56, 189, 248, 0.2);
    }
    div[data-testid="metric-container"] {
        background: #1e293b;
        border-radius: 12px;
        padding: 20px;
        border: 1px solid rgba(255,255,255,0.05);
        box-shadow: 0 4px 15px rgba(0,0,0,0.3);
    }
</style>
""", unsafe_allow_html=True)

# --- DATABASE CONNECTION ---
DB_FILE = "data/soc_fleet.db"

def load_data():
    if not os.path.exists(DB_FILE):
        return pd.DataFrame(columns=["mac_address", "ip_address", "role", "status"])
    try:
        conn = sqlite3.connect(DB_FILE)
        df = pd.read_sql_query("SELECT * FROM fleet_registry", conn)
        conn.close()
        return df
    except Exception as e:
        st.error(f"Failed to connect to SOC database: {e}")
        return pd.DataFrame()

# --- HEADER SECTION ---
col1, col2 = st.columns([4, 1])

with col1:
    st.title("🛡️ Sentinel-AI Command Center")
    st.markdown("<p style='color:#94a3b8;'>Real-time Zero Trust Fleet Overview</p>", unsafe_allow_html=True)

with col2:
    st.write("")
    st.write("")
    if st.button("🔄 Refresh Data", use_container_width=True):
        st.rerun()

# --- METRICS SECTION ---
df_fleet = load_data()

total_devices = len(df_fleet)
approved_devices = len(df_fleet[df_fleet['status'] == 'Approved']) if total_devices > 0 else 0
burned_devices = len(df_fleet[df_fleet['status'] == 'BURNED']) if total_devices > 0 else 0

mcol1, mcol2, mcol3 = st.columns(3)

with mcol1:
    st.metric(label="Total Devices Active", value=total_devices)

with mcol2:
    st.metric(label="✅ Approved & Trusted", value=approved_devices)

with mcol3:
    st.metric(label="🔥 BURNED (Quarantined)", value=burned_devices)

st.divider()

# --- FLEET TABLE SECTION ---
st.subheader("Global Zero Trust Directory")

if df_fleet.empty:
    st.info("No devices registered in the Sentinel-AI fleet yet. Await endpoints to authenticate.")
else:
    # Styling function for pandas
    def highlight_status(val):
        color = '#ef4444' if val == 'BURNED' else '#10b981' if val == 'Approved' else ''
        return f'color: {color}; font-weight: bold'

    styled_df = df_fleet.style.map(highlight_status, subset=['status'])
    
    st.dataframe(
        styled_df,
        use_container_width=True,
        hide_index=True,
        height=500
    )
