from elasticsearch import Elasticsearch
from flask_cors import CORS
from flask import Flask
import json

# === 1. เชื่อมต่อ Elasticsearch ===
es = Elasticsearch(
    ["http://localhost:9200"],  # เปลี่ยนเป็น host ขององค์กร
    basic_auth=("winlogbeat_user", "YourPassword")  # เปลี่ยนเป็น user/password จริง
)

app = Flask(__name__)
CORS(app)

# === 2. Query Winlogbeat logs ===
query = {
    "size": 1000,
    "query": {
        "bool": {
            "should": [
                {"terms": {"event_id": [400, 403, 600, 800]}},
                {"terms": {"event_id": [4103, 4104, 4105, 4106]}}
            ],
            "must": [
                {"terms": {"log_name": ["Windows PowerShell", "Microsoft-Windows-PowerShell/Operational"]}}
            ]
        }
    },
    "sort": [{"@timestamp": {"order": "desc"}}]
}

response = es.search(index="winlogbeat-*", body=query)

# === 3. Mapping Function ===
def map_to_mitre(log):
    # ตรวจจับ PowerShell execution
    if log.get("log_name") in ["Windows PowerShell", "Microsoft-Windows-PowerShell/Operational"]:
        if log.get("event_id") in [400, 403, 600, 800, 4103, 4104, 4105, 4106]:
            return {
                "tactic": "Execution",
                "technique": "Command and Scripting Interpreter",
                "sub_technique": "PowerShell (T1059.001)"
            }
    return {"tactic": "Unknown", "technique": "Unknown", "sub_technique": "Unknown"}

# === 4. Map logs ===
mapped_logs = []
for hit in response['hits']['hits']:
    source = hit['_source']
    source['mitre'] = map_to_mitre(source)
    mapped_logs.append(source)

# === 5. Output result ===
print(json.dumps(mapped_logs, indent=2))

with open("powershell_logs.json", "w") as f:
    json.dump(mapped_logs, f, indent=2)
