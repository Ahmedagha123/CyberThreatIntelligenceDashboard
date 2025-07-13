# 🛡️ Cyber Threat Intelligence Dashboard

An interactive dashboard that visualizes threat intelligence data from [AbuseIPDB](https://www.abuseipdb.com/), built with **Python**, **SQL Server**, and **Streamlit**.

![Dashboard Preview](assets/dashboard_preview.png)

---

## 🧠 Project Description

This project collects malicious IP data from AbuseIPDB, stores it in a structured SQL Server database, and visualizes it through a real-time interactive dashboard.

It’s designed for security analysts, red teams, or anyone building their threat intelligence skills.

---

## 📁 Project Structure

| File | Description |
|------|-------------|
| `abuseipdb_import.py` | Fetches data from AbuseIPDB and inserts into SQL Server |
| `dashboard.py` | Streamlit app to visualize threats by category, country, and severity |
| `SQLQuery1.sql` | Creates database tables (`Threats`, `Countries`, `Categories`, `Severities`) |

---

## 🔧 Technologies Used

- **Python 3.11**
- **SQL Server**
- **Streamlit**
- **Plotly**
- **pyodbc**
- **AbuseIPDB API**

---

## 🚀 How to Run the Project

### 1. Setup the Database

- Open `SQLQuery1.sql` in SQL Server and run it to create all necessary tables.

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
