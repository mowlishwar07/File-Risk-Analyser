from pymongo import MongoClient

# MongoDB Connection
client = MongoClient("mongodb://localhost:27017/")
db = client["file_risk_analyser"]

collection = db["scan_history"]
hash_collection = db["malware_hashes"]