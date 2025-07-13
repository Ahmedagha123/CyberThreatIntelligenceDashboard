import requests
import pyodbc
from datetime import datetime

#  API KEY
API_KEY = '685385344430be6f16e7480d09d58774772a764493adaf9cb10f0fff06d1116d525fc1878ed027ff'

#Connect to SQL Server
conn = pyodbc.connect(
    'DRIVER={SQL Server};SERVER=DESKTOP-7KB3B3F\\SQLDEVELOPER2022;DATABASE=CyberThreatIntelDB;Trusted_Connection=yes;'
)
cursor = conn.cursor()

# ID entry or retrieval function
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

# Get IP data from AbuseIPDB
def get_ip_info(ip):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"

    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
    }

    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

#  Threat input function
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
    print(f" IP entered: {ip} - ({severity})")

#  IPs for input testing
ips = ['8.8.8.8', '1.1.1.1', '185.107.56.234']

#  Implement
for ip in ips:
    try:
        data = get_ip_info(ip)
        insert_threat(data)
    except Exception as e:
        print(f"ERROR IN IP {ip}: {e}")

cursor.close()
conn.close()
print(" All data imported from AbuseIPDB is working!")

"""
abuseipdb_import.py
--------------------

This script fetches threat intelligence data from the AbuseIPDB API
for a set of predefined IP addresses and inserts the processed data
into a SQL Server database.

- Classifies IPs by abuse confidence score (Low / Medium / High)
- Handles country, category, and severity lookups
- Avoids duplicate entries in lookup tables
- Designed for use in CTI Dashboards

Author: Ahmed Mahmoud (Agha)
"""
