# 🔍 File Risk Analyzer

A Django-based web application that analyzes uploaded files to detect potential security risks using hash-based matching and heuristic analysis. 
The system generates unique file hashes, compares them with known malicious signatures, and applies rule-based checks to identify suspicious files.
It also stores scan history in MongoDB, enabling efficient tracking and analysis of previously scanned files.

---

## 🚀 Features

- 📂 File upload and scanning  
- 🔐 Hash-based malware detection  
- ⚠️ Risk score calculation  
- 🧠 Heuristic analysis  
- 📊 Scan history tracking  
- 🗄️ MongoDB integration  

---

## 🛠️ Tech Stack

- Backend: Django (Python)  
- Database: MongoDB (PyMongo)  
- Frontend: HTML, CSS  

---

## ⚙️ Setup

### 1. Clone the repository
```bash
git clone https://github.com/mowlishwar07/File-Risk-Analyser.git
cd File-Risk-Analyser
```

### 2. Create virtual environment
```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

---

## 🗄️ MongoDB Setup

1. Install MongoDB (Community Edition) with MongoDB Compass

2. Start MongoDB server:
```bash
mongod
```

3. Default connection:
```
mongodb://localhost:27017/
```

---

### 🚀 Load the given hashes in MongoDB
```bash
python load_hashes.py
```

---

## 🔐 Malware Hash Data

The project expects malware hashes stored in MongoDB.

**Database:**
- file_risk_analyser
  
**Collections:**
- malware_hashes   (stores known file hashes)  
- scan_history     (stores scan results and history)  

**Example document (for malware_hashes):**
```json
{
  "hash": "example_hash_here"
}
```

---

## ▶️ Run the Project

```bash
python manage.py runserver
```

Open:
```
http://127.0.0.1:8000/
```

---

## 👨‍💻 Author

Mowlishwar T
