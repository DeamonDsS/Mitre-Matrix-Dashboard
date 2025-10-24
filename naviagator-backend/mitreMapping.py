from flask import Flask, jsonify
from flask_cors import CORS
from elasticsearch import Elasticsearch

app = Flask(__name__)
CORS(app)  # อนุญาต cross-origin จาก frontend

# เชื่อม Elasticsearch
es = Elasticsearch("http://localhost:9200")  # เปลี่ยน URL/port ตามเซิร์ฟเวอร์ของคุณ

# Mapping Windows Event ID → MITRE ATT&CK Technique ID (ตัวอย่างหลัก ๆ)
EVENT_TO_TECH = {
    "4624": "T1078",  # Account Logon
    "4625": "T1110",  # Failed Logon
    "4672": "T1098",  # Special Privileges Assigned
    "4688": "T1059",  # Process Creation
    "4689": "T1059",  # Process Termination
    "4697": "T1543",  # Service Installed
    "4700": "T1569",  # Scheduled Task/Job
    "4702": "T1053",  # Scheduled Task Updated
    "4720": "T1136",  # User Account Created
    "4722": "T1098",  # User Account Enabled
    "4725": "T1098",  # User Account Disabled
    "4726": "T1098",  # User Account Deleted
    "4732": "T1075",  # Security Group Changed
    "4733": "T1075",  # Security Group Changed
    "4740": "T1078",  # Account Locked Out
    "1102": "T1070",  # Log Clear
    "16384": "T1547", # Software/Service Persistence
    # สามารถเพิ่มเพิ่มเติมตามความต้องการ
}

def map_event_to_tech(event):
    code = str(event.get("event", {}).get("code", ""))
    cmd = event.get("process", {}).get("command_line", "") or ""
    parent = event.get("process", {}).get("parent", {}).get("name", "")

    if code == "4624":
        # successful logon — แต่ต้องเช็ค context
        if event.get("logon", {}).get("type") == 3:  # network logon
            return "T1078"  # Valid Accounts
        return "T1078"

    if code == "4688":
        if "powershell" in cmd.lower():
            return "T1059.001"  # PowerShell
        if "schtasks" in cmd.lower() or parent.lower().endswith("taskeng.exe"):
            return "T1053"  # Scheduled Task
        return "T1059"  # generic command execution

    if code == "1102":
        return "T1070"  # Indicator removal

    # default
    return "T0000"
    

@app.route("/")
def index():
    return {"status": "Backend running. Go to /api/layer/latest"}

@app.route("/api/layer/latest")
def get_latest_layer():
    # Query Elasticsearch (แก้ index pattern ให้ตรง)
    result = es.search(index="winlogbeat-*", size=100, query={"match_all": {}})
    techniques = []

    for hit in result["hits"]["hits"]:
        src = hit["_source"]
        event_id = str(src.get("event", {}).get("code", "0"))
        severity = src.get("event", {}).get("severity", 50)
        comment = src.get("message", "")
        comment = comment.replace("\n", " ").replace("\t", " ")[:120]

        techniques.append({
            "techniqueID": EVENT_TO_TECH.get(event_id, "T0000"),  # ถ้าไม่มี mapping → T0000
            "score": int(severity),
            "comment": comment
        })

    layer = {
        "version": "4.4",
        "name": "Elasticsearch Winlogbeat Mapping",
        "domain": "enterprise-attack",
        "techniques": techniques
    }

    return jsonify(layer)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
