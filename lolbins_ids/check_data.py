from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient('localhost', 27017)
db = client['lolbins_ids']

# Check what collections exist
print("Collections:", db.list_collection_names())

# Check if analysis reports exist
reports_count = db.analysis_reports.count_documents({})
print(f"Analysis reports: {reports_count}")

# Check other collections
alerts_count = db.alerts.count_documents({})
print(f"Alerts: {alerts_count}")

process_history_count = db.process_history.count_documents({})
print(f"Process history records: {process_history_count}")