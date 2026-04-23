import hashlib
import os
from datetime import datetime
from django.shortcuts import render
from pymongo import MongoClient

# -----------------------
# MongoDB Connection
# -----------------------
client = MongoClient("mongodb://localhost:27017/")
db = client["file_risk_analyser"]

collection = db["scan_history"]
hash_collection = db["malware_hashes"]

# -----------------------
# File Extensions
# -----------------------
SCRIPT_EXTENSIONS = (".txt", ".bat", ".cmd", ".vbs", ".js", ".py", ".ps1")
SUSPICIOUS_EXTENSIONS = (
    ".exe", ".dll", ".scr", ".msi", ".jar",
    ".vbe", ".wsf", ".hta", ".lnk"
)

# -----------------------
# File Hashing
# -----------------------
def get_file_hash(file):
    file.seek(0)
    hasher = hashlib.sha256()
    for chunk in file.chunks():
        hasher.update(chunk)
    file.seek(0)
    return hasher.hexdigest()

# -----------------------
# Heuristic Scan
# -----------------------
def heuristic_scan(file):
    score = 0
    found_keywords = []

    filename = file.name.lower()
    _, ext = os.path.splitext(filename)

    try:
        file.seek(0)
        content = file.read().decode(errors="ignore").lower()
    except:
        content = ""

    danger_keywords = [
        "trojan", "ransomware", "rootkit", "keylogger",
        "backdoor", "exploit", "reverse shell",
        "meterpreter", "privilege escalation",
        "credential steal", "password dump",
        "shellcode", "autorun"
    ]

    suspicious_keywords = [
        "powershell", "cmd", "taskkill", "shutdown",
        "delete", "del", "format", "download",
        "invoke-webrequest", "curl", "wget",
        "exec", "system(", "os.system",
        "subprocess", "chmod", "net user",
        "ipconfig", "whoami"
    ]

    # Scan only script files
    if ext in SCRIPT_EXTENSIONS:
        for word in danger_keywords:
            if word in content:
                score += 25
                found_keywords.append(word)

        for word in suspicious_keywords:
            if word in content:
                score += 10
                found_keywords.append(word)

    # Extension-based scoring
    if ext in (".bat", ".cmd", ".ps1"):
        score += 15
    elif ext == ".txt":
        score += 5

    score = min(score, 100)

    if score >= 70:
        return "Danger", found_keywords, score
    elif score >= 35:
        return "Suspicious", found_keywords, score
    else:
        return "Safe", found_keywords, score


# -----------------------
# Views
# -----------------------
def index(request):
    return render(request, "index.html")


def scan_file(request):
    if request.method == "POST":
        scan_type = request.POST.get("scan_type")

        # =======================
        # FOLDER SCAN
        # =======================
        if scan_type == "folder":
            files = request.FILES.getlist("files")
            results = []

            for file in files:
                file_hash = get_file_hash(file)
                hash_entry = hash_collection.find_one({"hash": file_hash})

                # File info
                file.seek(0)
                file_size_kb = round(len(file.read()) / 1024, 2)
                file.seek(0)
                _, ext = os.path.splitext(file.name.lower())

                keywords = []

                # HASH CHECK
                if hash_entry:
                    status = "Danger"
                    method = "Hash"
                    risk_score = 100

                else:
                    # Suspicious extension but no hash match
                    if ext in SUSPICIOUS_EXTENSIONS:
                        status = "Safe"
                        method = "Hash + Heuristic"
                        risk_score = None

                    else:
                        status, keywords, risk_score = heuristic_scan(file)

                        if status in ["Danger", "Suspicious"]:
                            method = "Heuristic"
                        else:
                            method = "Hash + Heuristic"
                            risk_score = None  # ❌ Hide for Safe

                result = {
                    "filename": file.name,
                    "file_size_kb": file_size_kb,
                    "status": status,
                    "method": method,
                    "risk_score": risk_score
                }

                # Save to DB
                collection.insert_one({
                    "filename": file.name,
                    "file_size_kb": file_size_kb,
                    "status": status,
                    "method": method,
                    "risk_score": risk_score,
                    "keywords": keywords,
                    "time": datetime.now()
                })

                results.append(result)

            return render(request, "result.html", {"results": results})

        # =======================
        # SINGLE FILE SCAN
        # =======================
        elif scan_type == "file":
            file = request.FILES.get("file")
            file_hash = get_file_hash(file)
            hash_entry = hash_collection.find_one({"hash": file_hash})

            # File info
            file.seek(0)
            file_size_kb = round(len(file.read()) / 1024, 2)
            file.seek(0)
            _, ext = os.path.splitext(file.name.lower())

            keywords = []

            # HASH CHECK
            if hash_entry:
                status = "Danger"
                method = "Hash"
                risk_score = 100

            else:
                if ext in SUSPICIOUS_EXTENSIONS:
                    status = "Safe"
                    method = "Hash + Heuristic"
                    risk_score = None

                else:
                    status, keywords, risk_score = heuristic_scan(file)

                    if status in ["Danger", "Suspicious"]:
                        method = "Heuristic"
                    else:
                        method = "Hash + Heuristic"
                        risk_score = None  # ❌ Hide for Safe

            result = {
                "filename": file.name,
                "file_size_kb": file_size_kb,
                "status": status,
                "method": method,
                "risk_score": risk_score
            }

            # Save to DB
            collection.insert_one({
                "filename": file.name,
                "file_size_kb": file_size_kb,
                "status": status,
                "method": method,
                "risk_score": risk_score,
                "keywords": keywords,
                "time": datetime.now()
            })

            return render(request, "result.html", result)

    return render(request, "index.html")


# -----------------------
# History View
# -----------------------
def history(request):
    data = collection.find().sort("time", -1)
    return render(request, "history.html", {"data": data})