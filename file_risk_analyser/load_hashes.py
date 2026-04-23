from pymongo import MongoClient
import json

client = MongoClient("mongodb://localhost:27017/")
db = client["file_risk_analyser"]
collection = db["malware_hashes"]

collection.create_index("hash", unique=True)

with open("scanner/malware_hashes.json", "r") as file:
    data = json.load(file)

try:
    if isinstance(data, list):
        collection.insert_many(data, ordered=False)
    else:
        collection.insert_one(data)

    print(" Malware hashes inserted successfully!")

except Exception as e:
    print(" Some duplicates may have been skipped.")
    print(e)