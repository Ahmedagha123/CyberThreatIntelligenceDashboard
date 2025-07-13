import streamlit as st
import pandas as pd
import pyodbc
import plotly.express as px
import requests
from datetime import datetime

# ✅ Database Connection
conn = pyodbc.connect(
    'DRIVER={SQL Server};SERVER=DESKTOP-7KB3B3F\\SQLDEVELOPER2022;DATABASE=CyberThreatIntelDB;Trusted_Connection=yes;'
)
cursor = conn.cursor()

# ✅ Helper Functions
def get_or_insert(table, column, value, id_column):
    cursor.execute(f"SELECT {id_column} FROM {table} WHERE {column} = ?", value)
    result = cursor.fetchone()
    if result:
        return result[0]
    cursor.execute(f"INSERT INTO {table} ({column}) VALUES (?);", value)
    cursor.execute("SELECT SCOPE_IDENTITY();")
    new_id = cursor.fetchone()[0]
    conn.commit()
    return new_id

def insert_threat(ip_data):
    ip = ip_data['data']['ipAddress']
    country = ip_data['data']['countryCode'] or 'Unknown'
    category = 'AbuseIP'
    severity = 'High' if ip_data['data']['abuseConfidenceScore'] > 50 else 'Medium'
    description = ip_data['data']['usageType'] or 'No Description'
    status = 'Active'
    source = 'AbuseIPDB'
    report_date = datetime.utcnow().strftime('%Y-%m-%d')

    category_id = get_or_insert('Categories', 'CategoryName', category, 'CategoryID')
    country_id = get_or_insert('Countries', 'CountryName', country, 'CountryID')
    source_id = get_or_insert('Sources', 'SourceName', source, 'SourceID')

    cursor.execute('''
        INSERT INTO Threats (
            ThreatName, CategoryID, Severity, SourceIP, CountryID, ReportDate,
            Description, Status, SourceID
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        f"Suspicious IP: {ip}", category_id, severity, ip, country_id,
        report_date, description, status, source_id
    ))
    conn.commit()

def get_ip_info(ip):
    API_KEY = '685385344430be6f16e7480d09d58774772a764493adaf9cb10f0fff06d1116d525fc1878ed027ff'
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {'Accept': 'application/json', 'Key': API_KEY}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def load_data():
    query = '''
    SELECT t.ThreatID, t.ThreatName, c.CategoryName, t.Severity, t.SourceIP,
           co.CountryName, t.ReportDate, t.Description, t.Status, s.SourceName
    FROM Threats t
    JOIN Categories c ON t.CategoryID = c.CategoryID
    JOIN Countries co ON t.CountryID = co.CountryID
    JOIN Sources s ON t.SourceID = s.SourceID
    '''
    return pd.read_sql(query, conn)

# ✅ Streamlit UI Setup
st.set_page_config(layout="wide")
st.title("🛡️ Cyber Threat Intelligence Dashboard")

# ✅ Import Threats Section
with st.expander("📥 Import Threats from AbuseIPDB"):
    if st.button("📡 Import New IPs"):
        ips = ['8.8.8.8', '1.1.1.1', '185.107.56.234']  # ← You can modify this list
        count = 0
        for ip in ips:
            try:
                data = get_ip_info(ip)
                insert_threat(data)
                count += 1
            except Exception as e:
                st.error(f"❌ Failed for IP {ip}: {e}")
        st.success(f"✅ Successfully inserted {count} new threats!")

# ✅ Load Data
data = load_data()

# ✅ Sidebar Filters
st.sidebar.header("🎛️ Filter Data")
countries = st.sidebar.multiselect("Country", options=data["CountryName"].unique())
categories = st.sidebar.multiselect("Threat Category", options=data["CategoryName"].unique())
statuses = st.sidebar.multiselect("Status", options=data["Status"].unique())

# ✅ Apply Filters
filtered_data = data
if countries:
    filtered_data = filtered_data[filtered_data["CountryName"].isin(countries)]
if categories:
    filtered_data = filtered_data[filtered_data["CategoryName"].isin(categories)]
if statuses:
    filtered_data = filtered_data[filtered_data["Status"].isin(statuses)]

# ✅ Display Table
st.subheader("📋 Cyber Threats")
st.dataframe(filtered_data, use_container_width=True)

# ✅ Bar Chart - Threats by Category
threats_by_category = filtered_data["CategoryName"].value_counts().reset_index()
threats_by_category.columns = ["Category", "Count"]
fig1 = px.bar(threats_by_category, x="Category", y="Count", title="📊 Threats by Category")
st.plotly_chart(fig1, use_container_width=True)

# ✅ Bar Chart - Threats by Country
threats_by_country = filtered_data["CountryName"].value_counts().reset_index()
threats_by_country.columns = ["Country", "Count"]
fig2 = px.bar(threats_by_country, x="Country", y="Count", title="🌍 Threats by Country")
st.plotly_chart(fig2, use_container_width=True)


"""
dashboard.py
-------------

This script creates an interactive Cyber Threat Intelligence Dashboard using Streamlit.

- Connects to SQL Server to fetch threat data
- Visualizes categories, countries, and severity levels
- Uses Plotly for rich and responsive charts
- Ideal for SOC teams, CTI analysts, or demoing threat insights

Author: Ahmed Mahmoud (Agha)
"""
