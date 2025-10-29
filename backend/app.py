from flask import Flask, jsonify
from flask_cors import CORS
from elasticsearch import Elasticsearch

app = Flask(__name__)
CORS(app)

# เชื่อมต่อ Elasticsearch
es = Elasticsearch("http://localhost:9200")

@app.route("/")
def index():
    return {"status": "Backend is running."}

@app.route("/api/layer/latest")
def get_latest_layer():
    # ค้นหาข้อมูลจาก Elasticsearch index winlogbeat-*
    query = {
        "size": 100,
        "query": {
            "match_all": {}
        }
    }

    result = es.search(index="winlogbeat-*", body=query)

    techniques = []
    for hit in result["hits"]["hits"]:
        src = hit["_source"]
        # ดึงข้อมูลบางส่วน (customize ตาม log ของคุณ)
        technique_id = src.get("event", {}).get("code", "T0000")
        severity = src.get("event", {}).get("severity", 50)
        message = src.get("message", "")

        EVENT_TO_TECH = {
            "4624": "T1078",  # Valid Accounts
            "4672": "T1098",  # Account Manipulation / Special Privileges
            "16384": "T1547", # Boot or Service Persistence (ตัวอย่าง)
        }

        techniques.append({
            "techniqueID": EVENT_TO_TECH.get(str(technique_id)),
            "score": int(severity),
            "comment": message[:120]  # limit ความยาว comment
        })

    # สร้าง layer JSON ให้ Navigator
    layer = {
        "version": "4.4",
        "name": "Elasticsearch Winlogbeat Mapping",
        "domain": "enterprise-attack",
        "techniques": techniques
    }

    return jsonify(layer)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
