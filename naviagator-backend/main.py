# main.py
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from elasticsearch import AsyncElasticsearch, Elasticsearch
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from datetime import datetime
import os
from dotenv import load_dotenv
import datetime
import json
from pathlib import Path


load_dotenv()

# --- Fix 2: Add Lifespan Context Manager for ES Client ---
es = None  # Global variable

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    global es
    ES_URL = os.getenv("ES_URL", "http://localhost:9200")
    ES_USER = os.getenv("ES_USER", "")
    ES_PASS = os.getenv("ES_PASS", "")
    ES_INDEX = os.getenv('ES_INDEX_NAME', '.ds-winlogbeats-9.1.5-*')
    
    if ES_USER and ES_PASS:
        es = AsyncElasticsearch([ES_URL], basic_auth=(ES_USER, ES_PASS))
    else:
        es = AsyncElasticsearch([ES_URL])
    
    print("✅ Elasticsearch client connected")
    yield
    
    # Shutdown - Close ES client properly
    if es:
        await es.close()
        print("✅ Elasticsearch client closed")

# Update FastAPI app with lifespan
app = FastAPI(
    title="MITRE ATT&CK Security Events API",
    lifespan=lifespan
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# # Elasticsearch Configuration
# ES_URL = os.getenv("ES_URL", "http://localhost:9200")
# ES_USER = os.getenv("ES_USER", "")
# ES_PASS = os.getenv("ES_PASS", "")
# ES_INDEX = os.getenv('ES_INDEX_NAME', '.ds-winlogbeats-9.1.5-*')

# Initialize Elasticsearch client
# if ES_USER and ES_PASS:
#     es = Elasticsearch([ES_URL], basic_auth=(ES_USER, ES_PASS))
# else:
#     es = Elasticsearch([ES_URL])

# --- (แก้ไข) ---
# Initialize Asynchronous Elasticsearch client
# เปลี่ยนไปใช้ AsyncElasticsearch เพื่อให้เข้ากับ FastAPI ได้ดีที่สุด
# if ES_USER and ES_PASS:
#     es = AsyncElasticsearch([ES_URL], basic_auth=(ES_USER, ES_PASS))
# else:
#     es = AsyncElasticsearch([ES_URL])
    
# Pydantic Models
class SearchRequest(BaseModel):
    search: Optional[str] = None
    tactic: Optional[str] = "all"
    severity: Optional[str] = "all"
    size: Optional[int] = 100

class MitreTechnique(BaseModel):
    id: str
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    severity: str
    timestamp: str
    platform: List[str]
    event_code: str
    host_name: str
    user_name: str
    process_name: str
    log_level: str
    channel: str
    source_ip : Optional[str] = None
    destination_ip: Optional[str] = None

class SearchRequest(BaseModel):
    search: Optional[str] = None
    tactic: Optional[str] = "all"
    severity: Optional[str] = "all"
    size: Optional[int] = 10
    page: Optional[int] = 1 # เพิ่ม page เข้ามา
    
class Technique(BaseModel):
    id: str
    eventIds: List[int]

class StatsRequest(BaseModel):
    search: Optional[str] = None
    tactic: Optional[str] = "all"
    severity: Optional[str] = "all"
    dayRange: Optional[int] = 7  # ✅ เพิ่ม dayRange parameter (default 7 วัน)
    techniques: Optional[List[Technique]] = []  # ✅ เพิ่มตรงนี้

class DateRange(BaseModel):
    start: str
    end: str

class MitreStatsRequest(BaseModel):
    esIndex: str
    techniques: List[Technique]
    dateRange: Optional[DateRange] = None  # Add this

MAPPING_PATH = Path(__file__).parent / "../public/data/enterprise-attack.json"
with open(MAPPING_PATH, "r", encoding="utf-8") as f:
    MITRE_MAPPING = json.load(f)

# MITRE ATT&CK Mapping
EVENT_SEVERITY_MAP = {
    # Security Events - Logon/Logoff
    "4624": {"severity": "low", "category": "Account Logon Success"},
    "4625": {"severity": "medium", "category": "Account Logon Failed"},
    "4634": {"severity": "low", "category": "Account Logged Off"},
    "4647": {"severity": "low", "category": "User Initiated Logoff"},
    "4648": {"severity": "medium", "category": "Logon Using Explicit Credentials"},
    "4672": {"severity": "high", "category": "Special Privileges Assigned"},
    "4768": {"severity": "low", "category": "Kerberos TGT Requested"},
    "4769": {"severity": "low", "category": "Kerberos Service Ticket"},
    "4771": {"severity": "high", "category": "Kerberos Pre-Auth Failed"},
    "4776": {"severity": "medium", "category": "Credential Validation Attempted"},
    
    # Process Events
    "4688": {"severity": "low", "category": "New Process Created"},
    "4689": {"severity": "low", "category": "Process Terminated"},
    
    # Account Management
    "4720": {"severity": "medium", "category": "User Account Created"},
    "4722": {"severity": "medium", "category": "User Account Enabled"},
    "4723": {"severity": "medium", "category": "Password Change Attempted"},
    "4724": {"severity": "medium", "category": "Password Reset Attempted"},
    "4725": {"severity": "medium", "category": "User Account Disabled"},
    "4726": {"severity": "medium", "category": "User Account Deleted"},
    "4732": {"severity": "high", "category": "Member Added to Security Group"},
    "4733": {"severity": "high", "category": "Member Removed from Security Group"},
    "4738": {"severity": "medium", "category": "User Account Changed"},
    "4740": {"severity": "high", "category": "User Account Locked Out"},
    "4756": {"severity": "high", "category": "Member Added to Universal Group"},
    
    # Service Events
    "4697": {"severity": "high", "category": "Service Installed"},
    "7045": {"severity": "high", "category": "Service Installed (System)"},
    "7036": {"severity": "low", "category": "Service State Changed"},
    "7040": {"severity": "medium", "category": "Service Start Type Changed"},
    
    # Security Log Events
    "1102": {"severity": "critical", "category": "Audit Log Cleared"},
    "1104": {"severity": "critical", "category": "Security Log Full"},
    "1105": {"severity": "high", "category": "Audit Log Cleared"},
    
    # Object Access
    "4656": {"severity": "low", "category": "Handle to Object Requested"},
    "4663": {"severity": "low", "category": "Object Access Attempted"},
    "4670": {"severity": "medium", "category": "Object Permissions Changed"},
    
    # Policy Change
    "4719": {"severity": "high", "category": "System Audit Policy Changed"},
    "4739": {"severity": "high", "category": "Domain Policy Changed"},
    
    # System Events
    "10016": {"severity": "low", "category": "DCOM Permission Error"},
    "7000": {"severity": "medium", "category": "Service Failed to Start"},
    "7001": {"severity": "medium", "category": "Service Dependency Failed"},
    "7034": {"severity": "medium", "category": "Service Crashed"},
    "6005": {"severity": "low", "category": "Event Log Service Started"},
    "6006": {"severity": "low", "category": "Event Log Service Stopped"},
    "6008": {"severity": "high", "category": "Unexpected Shutdown"},
    
    # Application Events
    "1000": {"severity": "medium", "category": "Application Error"},
    "1001": {"severity": "medium", "category": "Application Hang"},
    "1002": {"severity": "high", "category": "Application Crash"},
    
    # Windows Defender
    "1116": {"severity": "high", "category": "Malware Detected"},
    "1117": {"severity": "high", "category": "Malware Blocked"},
    "5001": {"severity": "medium", "category": "Real-time Protection Disabled"},
}

EVENT_TACTIC_MAP = {
    # Initial Access
    "4624": "Initial Access",
    "4625": "Initial Access",
    "4648": "Lateral Movement",
    
    # Execution
    "4688": "Execution",
    "4689": "Execution",
    
    # Persistence
    "4697": "Persistence",
    "7045": "Persistence",
    "4720": "Persistence",
    "7040": "Persistence",
    
    # Privilege Escalation
    "4672": "Privilege Escalation",
    "4732": "Privilege Escalation",
    "4756": "Privilege Escalation",
    
    # Defense Evasion
    "1102": "Defense Evasion",
    "1104": "Defense Evasion",
    "1105": "Defense Evasion",
    "4719": "Defense Evasion",
    "5001": "Defense Evasion",
    
    # Credential Access
    "4771": "Credential Access",
    "4776": "Credential Access",
    "4768": "Credential Access",
    "4769": "Credential Access",
    
    # Discovery
    "10016": "Discovery",
    "4656": "Discovery",
    "4663": "Discovery",
    
    # Impact
    "1116": "Impact",
    "1117": "Impact",
    "6008": "Impact",
    "7034": "Impact",
}

# MITRE ATT&CK T1059.001 - PowerShell specific mapping
POWERSHELL_T1059_001_KEYWORDS = {
    "technique_id": "T1059.001",
    "technique_name": "Command and Scripting Interpreter: PowerShell",
    "tactic": "Execution",
    "keywords": [
        "powershell.exe", "-enc", "-encodedcommand", "iex", "invoke-expression",
        "invoke-command", "invoke-webrequest", "downloadstring", "downloadfile",
        "-nop", "-noprofile", "-w hidden", "-windowstyle hidden", "bypass",
        "set-executionpolicy bypass", "frombase64string"
    ]
}

# ฟังก์ชันช่วยคำนวณ severity จาก event codes
def get_technique_severity(event_ids: List[int]) -> str:
    """
    คำนวณ severity จาก event codes ที่เกี่ยวข้องกับ technique
    ใช้ severity ที่สูงที่สุดจาก event codes ทั้งหมด
    """
    severities = []
    for event_id in event_ids:
        event_code = str(event_id)
        if event_code in EVENT_SEVERITY_MAP:
            severities.append(EVENT_SEVERITY_MAP[event_code]["severity"])
    
    # ใช้ severity ที่สูงที่สุด (ตามลำดับ: critical > high > medium > low)
    if "critical" in severities:
        return "critical"
    elif "high" in severities:
        return "high"
    elif "medium" in severities:
        return "medium"
    elif "low" in severities:
        return "low"
    else:
        return "none"
    
def calculate_technique_severity(event_ids: List[int]) -> str:
    """
    คำนวณ severity ของ technique จาก event IDs
    โดยเลือก severity ที่สูงที่สุดจาก event codes ทั้งหมด
    """
    severity_priority = {
        'critical': 4,
        'high': 3,
        'medium': 2,
        'low': 1,
        'none': 0
    }
    
    max_severity = 'none'
    max_priority = 0
    
    for event_id in event_ids:
        event_code = str(event_id)
        event_info = EVENT_SEVERITY_MAP.get(event_code, {
            "severity": "low",
            "category": "Unknown Event"
        })
        severity = event_info["severity"]
        priority = severity_priority.get(severity, 0)
        
        if priority > max_priority:
            max_priority = priority
            max_severity = severity
    
    return max_severity


def map_event_to_mitre(hit: Dict[str, Any]) -> Dict[str, Any]:
    """Map Elasticsearch event to MITRE ATT&CK format"""
    source = hit.get("_source", {})
    
    # Extract event code
    event_code = (
        source.get("event", {}).get("code") or
        str(source.get("winlog", {}).get("event_id", "")) or
        "unknown"
    )
    
    event_info = EVENT_SEVERITY_MAP.get(event_code, {
        "severity": "medium",
        "category": "Unknown Event"
    })
    
    # Extract user information
    user_name = (
        source.get("user", {}).get("name") or
        source.get("winlog", {}).get("event_data", {}).get("TargetUserName") or
        source.get("winlog", {}).get("event_data", {}).get("SubjectUserName") or
        (source.get("related", {}).get("user", []) or ["N/A"])[0]
    )
    
    # Extract host information
    host_name = (
        source.get("host", {}).get("name") or
        source.get("host", {}).get("hostname") or
        source.get("agent", {}).get("name") or
        source.get("winlog", {}).get("computer_name") or
        "Unknown Host"
    )
    
    # Extract process information
    process_name = (
        source.get("process", {}).get("name") or
        source.get("process", {}).get("executable") or
        source.get("winlog", {}).get("event_data", {}).get("ProcessName") or
        source.get("winlog", {}).get("event_data", {}).get("NewProcessName") or
        ""
    )
    
    # Extract channel
    channel = (
        source.get("winlog", {}).get("channel") or
        source.get("event", {}).get("module") or
        "Unknown"
    )
    
    # Extract log level
    log_level = (
        source.get("log", {}).get("level") or
        source.get("winlog", {}).get("level") or
        "info"
    )
    
    # Build description
    description = source.get("message", "No description available")
    if len(description) > 250:
        first_paragraph = description.split("\n\n")[0]
        if first_paragraph and len(first_paragraph) <= 250:
            description = first_paragraph
        else:
            description = description[:250] + "..."
    
    # Extract platform
    platform = (
        source.get("host", {}).get("os", {}).get("family") or
        source.get("host", {}).get("os", {}).get("platform") or
        "Windows"
    )

    # ตรวจสอบจาก field ที่เป็นไปได้หลายๆ แห่ง
    source_ip = (
        source.get("source", {}).get("ip") or
        source.get("winlog", {}).get("event_data", {}).get("IpAddress") or
        source.get("related", {}).get("ip", [None])[0] or
        None
    )

    destination_ip = (
        source.get("destination", {}).get("ip") or
        source.get("winlog", {}).get("event_data", {}).get("DestinationIp") or
        None
    )

    
    return {
        "id": hit["_id"],
        "technique_id": f"Event-{event_code}",
        "technique_name": event_info["category"],
        "tactic": EVENT_TACTIC_MAP.get(event_code, "Discovery"),
        "description": description,
        "severity": event_info["severity"],
        "timestamp": source.get("@timestamp", datetime.utcnow().isoformat()),
        "platform": [platform],
        "event_code": event_code,
        "host_name": host_name,
        "user_name": user_name,
        "process_name": process_name,
        "log_level": log_level,
        "channel": channel,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
    }

@app.get("/")
async def root():
    """API health check"""
    # (แก้ไข) เพิ่ม await
    es_connected = await es.ping()
    es_info = {}
    if es_connected:
        es_info = await es.info()

    return {
        "status": "ok",
        "service": "MITRE ATT&CK Security Events API",
        "version": "1.0.0",
        "elasticsearch": {
            "connected": es.ping(),
            "url": ES_URL
        }
    }

@app.post("/api/search")
async def search_events(
    index: str = Query(..., description="Elasticsearch index pattern"),
    request: SearchRequest = SearchRequest()
):
    try:
        query = {"bool": {"must": [], "filter": []}} # แยก must (search) กับ filter

        # 2. ย้าย Logic การกรองมาไว้ใน Query
        if request.search:
            query["bool"]["must"].append({
                "multi_match": {
                    "query": request.search,
                    "fields": ["message", "host.name", "user.name", "winlog.event_data.*",  "source.ip", "destination.ip"],
                    "fuzziness": "AUTO"
                }
            })

        if request.tactic and request.tactic != "all":
            # ค้นหา event_code ที่ตรงกับ tactic แล้วสร้าง query
            event_codes_for_tactic = [code for code, tac in EVENT_TACTIC_MAP.items() if tac == request.tactic]
            if event_codes_for_tactic:
                 query["bool"]["filter"].append({"terms": {"event.code": event_codes_for_tactic}})

        if request.severity and request.severity != "all":
            # ค้นหา event_code ที่ตรงกับ severity แล้วสร้าง query
            event_codes_for_severity = [code for code, info in EVENT_SEVERITY_MAP.items() if info["severity"] == request.severity]
            if event_codes_for_severity:
                query["bool"]["filter"].append({"terms": {"event.code": event_codes_for_severity}})

        # 3. คำนวณ 'from' สำหรับ Elasticsearch pagination
        from_value = (request.page - 1) * request.size

        body = {
            "query": query if query["bool"]["must"] or query["bool"]["filter"] else {"match_all": {}},
            "size": request.size,
            "from": from_value, # ระบุว่าจะข้ามไปกี่รายการ
            "sort": [{"@timestamp": {"order": "desc"}}]
        }

        response = await es.search(index=index, body=body)

        events = [map_event_to_mitre(hit) for hit in response["hits"]["hits"]]

        # 4. ส่ง total ที่แท้จริงจาก Elasticsearch กลับไป
        return {
            "total": response["hits"]["total"]["value"], # ใช้ total จาก ES โดยตรง
            "events": events,
            "page": request.page,
            "size": request.size,
            "took": response["took"],
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/stats")
async def get_statistics(
    index: str = Query(..., description="Elasticsearch index pattern"),
    request: StatsRequest = StatsRequest()
):
    try:
        # 3. สร้าง Query ที่เหมือนกับใน /api/search เพื่อให้ผลลัพธ์ตรงกัน
        query = {"bool": {"must": [], "filter": []}}

        if request.search:
            query["bool"]["must"].append({
                "multi_match": {
                    "query": request.search,
                    "fields": ["message", "host.name", "user.name", "winlog.event_data.*"],
                    "fuzziness": "AUTO"
                }
            })

        if request.tactic and request.tactic != "all":
            event_codes_for_tactic = [code for code, tac in EVENT_TACTIC_MAP.items() if tac == request.tactic]
            if event_codes_for_tactic:
                 query["bool"]["filter"].append({"terms": {"event.code": event_codes_for_tactic}})

        if request.severity and request.severity != "all":
            event_codes_for_severity = [code for code, info in EVENT_SEVERITY_MAP.items() if info["severity"] == request.severity]
            if event_codes_for_severity:
                query["bool"]["filter"].append({"terms": {"event.code": event_codes_for_severity}})

        # 4. สร้าง Aggregations Query
        aggs = {
            "severity_counts": {
                "terms": {
                    # เราต้องหาทาง map severity กลับไปที่ event.code
                    # วิธีที่ง่ายกว่าคือ aggregate จาก field ที่เราสร้างขึ้นตอน map
                    # แต่เพื่อความเรียบง่ายในตอนนี้ เราจะทำแบบจำลองก่อน
                    # หมายเหตุ: การทำ Aggregation บน severity ตรงๆ จะซับซ้อนถ้าไม่มี field โดยเฉพาะ
                    # ดังนั้นเราจะดึงค่า severity จากการ map event code ก่อน
                    "script": {
                        "source": """
                            String eventCode = doc['event.code'].value;
                            if (params.severity_map.containsKey(eventCode)) {
                                return params.severity_map[eventCode];
                            }
                            return 'unknown';
                        """,
                        "params": {
                            "severity_map": {code: info["severity"] for code, info in EVENT_SEVERITY_MAP.items()}
                        }
                    },
                    "size": 10 # จำนวน severity ที่เป็นไปได้
                }
            },
            "tactic_counts": {
                 "cardinality": { # ใช้นับจำนวน unique
                    "script": {
                         "source": """
                            String eventCode = doc['event.code'].value;
                            if (params.tactic_map.containsKey(eventCode)) {
                                return params.tactic_map[eventCode];
                            }
                            return 'Discovery'; // default tactic
                        """,
                        "params": {
                            "tactic_map": EVENT_TACTIC_MAP
                        }
                    }
                 }
            }
        }

        # 5. ส่ง Request ไปยัง Elasticsearch
        response = await es.search(
            index=index,
            body={
                "query": query if query["bool"]["must"] or query["bool"]["filter"] else {"match_all": {}},
                "size": 0, # เราไม่ต้องการ document, เอาแค่ผล aggregation
                "aggs": aggs
            }
        )

        # 6. แปลงผลลัพธ์ Aggregation ให้อยู่ในรูปแบบที่ใช้งานง่าย
        aggs_result = response["aggregations"]
        severity_buckets = aggs_result.get("severity_counts", {}).get("buckets", [])
        
        stats_data = {
            "total": response["hits"]["total"]["value"],
            "critical": next((b["doc_count"] for b in severity_buckets if b["key"] == "critical"), 0),
            "high": next((b["doc_count"] for b in severity_buckets if b["key"] == "high"), 0),
            "medium": next((b["doc_count"] for b in severity_buckets if b["key"] == "medium"), 0),
            "low": next((b["doc_count"] for b in severity_buckets if b["key"] == "low"), 0),
            "tactics": aggs_result.get("tactic_counts", {}).get("value", 0)
        }

        return stats_data

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/tactics")
async def get_tactics():
    """Get all MITRE ATT&CK tactics"""
    unique_tactics = sorted(set(EVENT_TACTIC_MAP.values()))
    return {"tactics": unique_tactics}

@app.get("/api/health")
async def health_check():
    """Detailed health check"""
    es_healthy = await es.ping()
    es_info = {}
    if es_healthy:
        es_info = await es.info()

    return {
        "status": "healthy" if es_healthy else "unhealthy",
        "elasticsearch": {
            "connected": es_healthy,
            "url": ES_URL,
            "cluster_name": es.info()["cluster_name"] if es_healthy else None
        },
        "timestamp": datetime.utcnow().isoformat()
    }

# เพิ่มฟังก์ชันนี้ต่อจาก endpoint อื่นๆ เช่น @app.get("/api/health")

# @app.post("/api/powershell-events", summary="Search for PowerShell T1059.001 related events")
# async def search_powershell_events(
#     index: str = Query(..., description="Elasticsearch index pattern"),
#     request: SearchRequest = SearchRequest()
# ):
#     """
#     Searches for security events related to PowerShell execution (T1059.001),
#     often associated with the 'Execution' tactic.
#     """
#     try:
#         # 1. สร้าง Query พื้นฐานสำหรับ PowerShell
#         # เราจะค้นหาจาก Event Code 4688 (Process Creation) และคำสำคัญของ PowerShell
#         query = {
#             "bool": {
#                 "must": [],
#                 "filter": [
#                     # จำกัดให้ค้นหาเฉพาะเหตุการณ์การสร้างโปรเซส (Process Creation)
#                     {"term": {"event.code": "4688"}}
#                 ],
#                 "should": [
#                     # ให้คะแนนสูงถ้าเจอ keywords ที่อันตราย
#                     {"wildcard": {"process.command_line": "*powershell*"}},
#                     {"terms": {"process.command_line": POWERSHELL_T1059_001_KEYWORDS["keywords"]}}
#                 ],
#                 "minimum_should_match": 1 # ต้องมีอย่างน้อย 1 เงื่อนไขใน should ที่ตรง
#             }
#         }

#         # 2. เพิ่มเงื่อนไขการค้นหาจาก Request (ถ้ามี)
#         if request.search:
#             query["bool"]["must"].append({
#                 "multi_match": {
#                     "query": request.search,
#                     "fields": ["message", "process.command_line", "host.name", "user.name", "source.ip", "destination.ip"],
#                     "fuzziness": "AUTO"
#                 }
#             })

#         # 3. จัดการ Pagination
#         from_value = (request.page - 1) * request.size

#         body = {
#             "query": query,
#             "size": request.size,
#             "from": from_value,
#             "sort": [{"@timestamp": {"order": "desc"}}]
#         }

#         # 4. ส่ง Query ไปยัง Elasticsearch
#         response = await es.search(index=index, body=body)

#         # 5. Map ผลลัพธ์ที่ได้กลับมา
#         events = []
#         for hit in response["hits"]["hits"]:
#             # ใช้ map_event_to_mitre เดิมเพื่อดึงข้อมูลพื้นฐาน
#             mapped_event = map_event_to_mitre(hit)
            
#             # ตรวจสอบและอัปเดตข้อมูลสำหรับ T1059.001 โดยเฉพาะ
#             command_line = hit.get("_source", {}).get("process", {}).get("command_line", "").lower()
            
#             # หากเจอ keyword ที่เกี่ยวข้อง ให้ทำการ override ข้อมูลบางส่วน
#             if any(keyword in command_line for keyword in POWERSHELL_T1059_001_KEYWORDS["keywords"]):
#                 mapped_event["technique_id"] = POWERSHELL_T1059_001_KEYWORDS["technique_id"]
#                 mapped_event["technique_name"] = POWERSHELL_T1059_001_KEYWORDS["technique_name"]
#                 mapped_event["tactic"] = POWERSHELL_T1059_001_KEYWORDS["tactic"]
#                 mapped_event["severity"] = "high" # กำหนดเป็น 'high' เมื่อเจอการใช้งานที่น่าสงสัย
#                 mapped_event["description"] = f"Suspicious PowerShell execution detected. Command: {command_line[:200]}..."

#             events.append(mapped_event)

#         return {
#             "total": response["hits"]["total"]["value"],
#             "events": events,
#             "page": request.page,
#             "size": request.size,
#             "took": response["took"],
#         }

#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Error searching PowerShell events: {str(e)}")



# # --- (ส่วนของ get_technique_stats ที่แก้ไขใหม่ทั้งหมด) ---

# @app.post("/api/technique-stats", summary="Get statistics for multiple MITRE techniques")
# async def get_technique_stats(request: MitreStatsRequest):
#     """
#     Receives an index and a list of MITRE techniques, then fetches
#     detection statistics for each from Elasticsearch in a single batch request.
#     """
#     try:
#         searches = []
#         # สร้าง Multi-Search (msearch) body
#         # เราจะส่ง query ทั้งหมดไปใน request เดียว
#         for tech in request.techniques:
#             if tech.eventIds:
#                 # ส่วน Header ของ msearch
#                 searches.append({"index": request.esIndex})
#                 # ส่วน Body (Query) ของ msearch
#                 searches.append({
#                     "query": {
#                         "bool": {
#                             "must": [
#                                 {"terms": {"event.code": tech.eventIds}},
#                                 {"range": {"@timestamp": {"gte": "now-7d"}}}
#                             ]
#                         }
#                     },
#                     "size": 0, # ไม่ต้องการผลลัพธ์, เอาแค่ count
#                     "aggs": {
#                         "latest": {"max": {"field": "@timestamp"}}
#                     }
#                 })

#         # ถ้าไม่มีเทคนิคที่ต้อง query ก็คืนค่าว่างกลับไป
#         if not searches:
#             return {tech.id: {"count": 0, "severity": "none", "lastSeen": None} for tech in request.techniques}

#         # --- ใช้ msearch (Multi-Search) ของ Elasticsearch ---
#         # นี่คือวิธีที่มีประสิทธิภาพที่สุดในการทำ Batch Query
#         response = await es.msearch(body=searches)

#         # --- ประมวลผลผลลัพธ์จาก msearch ---
#         all_stats = {}
#         tech_index = 0
#         for tech in request.techniques:
#             if not tech.eventIds:
#                 all_stats[tech.id] = {"count": 0, "severity": "none", "lastSeen": None}
#                 continue

#             # ดึงผลลัพธ์ที่ตรงกับเทคนิคนี้
#             result = response['responses'][tech_index]
#             tech_index += 1

#             if result.get("error"):
#                 all_stats[tech.id] = {"count": 0, "severity": "error", "lastSeen": None, "details": result["error"]}
#                 continue

#             count = result.get("hits", {}).get("total", {}).get("value", 0)
#             severity = 'critical' if count > 70 else 'high' if count > 40 else 'medium' if count > 10 else 'low' if count > 0 else 'none'
#             last_seen = result.get("aggregations", {}).get("latest", {}).get("value_as_string")

#             all_stats[tech.id] = {
#                 "count": count,
#                 "severity": severity,
#                 "lastSeen": last_seen,
#             }

#         return all_stats

#     except Exception as e:
#         # ส่งคืน Error ที่มีความหมายมากขึ้นสำหรับ Debug
#         raise HTTPException(status_code=500, detail=f"Error in technique-stats: {str(e)}")

#With real field
# @app.post("/api/technique-stats", summary="Get statistics for MITRE techniques from XSIAM fields")
# async def get_technique_stats(request: MitreStatsRequest):
#     """
#     Fetches detection statistics by aggregating directly from Palo Alto XSIAM's
#     MITRE mapping fields in Elasticsearch. This method is more accurate and efficient.
#     """
#     try:
#         # 1. สร้าง Aggregation Query หลัก
#         # เราจะใช้ Terms Aggregation เพื่อจัดกลุ่มตาม Technique ID และชื่อ
#         # เราต้องใช้ .keyword เพื่อให้แน่ใจว่าเป็นการจัดกลุ่มจากค่าเต็มๆ ของ String
#         aggregation_query = {
#             "size": 0,  # เราไม่ต้องการ hits, เอาแค่ผล aggregation
#             "query": {
#                 "bool": {
#                     "must": [
#                         # กรองข้อมูลเฉพาะที่มีการระบุ Technique ID
#                         {"exists": {"field": "palo-xsiam.mitre_technique_id_and_name.keyword"}},
#                         # กรองข้อมูลตามช่วงเวลา
#                         {"range": {"@timestamp": {"gte": "now-7d"}}}
#                     ]
#                 }
#             },
#             "aggs": {
#                 "techniques": {
#                     "terms": {
#                         "field": "palo-xsiam.mitre_technique_id_and_name.keyword",
#                         "size": 500  # จำนวนเทคนิคสูงสุดที่คาดว่าจะเจอ
#                     },
#                     "aggs": {
#                         # Sub-aggregation: หา timestamp ล่าสุดของแต่ละเทคนิค
#                         "latest": {
#                             "max": {"field": "@timestamp"}
#                         }
#                     }
#                 }
#             }
#         }

#         # 2. ส่ง Query ไปยัง Elasticsearch
#         response = await es.search(index=ES_INDEX, body=aggregation_query)

#         # 3. ประมวลผลผลลัพธ์จาก Aggregation
#         detected_stats = {}
#         # ดึงข้อมูลจาก buckets ที่ได้จากการ aggregation
#         for bucket in response.get("aggregations", {}).get("techniques", {}).get("buckets", []):
#             key = bucket.get("key")  # เช่น "T1491 - Defacement"
#             if not key or " - " not in key:
#                 continue

#             # แยก Technique ID และชื่อออกจากกัน
#             parts = key.split(" - ", 1)
#             technique_id = parts[0]
#             # technique_name = parts[1] # เราไม่จำเป็นต้องใช้ชื่อในตอนนี้

#             count = bucket.get("doc_count", 0)
#             last_seen = bucket.get("latest", {}).get("value_as_string")
#             severity = 'critical' if count > 70 else 'high' if count > 40 else 'medium' if count > 10 else 'low'

#             # เก็บผลลัพธ์โดยใช้ Technique ID เป็น key
#             detected_stats[technique_id] = {
#                 "count": count,
#                 "severity": severity,
#                 "lastSeen": last_seen,
#             }

#         # 4. สร้างผลลัพธ์สุดท้ายให้ตรงกับที่ Frontend คาดหวัง
#         # โดยวนลูปจากเทคนิคทั้งหมดที่ Frontend รู้จัก
#         all_stats = {}
#         for tech in request.techniques:
#             # ถ้าเจอสถิติของเทคนิคนี้ใน `detected_stats` ก็ใช้ค่านั้น
#             if tech.id in detected_stats:
#                 all_stats[tech.id] = detected_stats[tech.id]
#             # ถ้าไม่เจอ ก็หมายความว่าเทคนิคนี้ยังไม่ถูกตรวจจับ
#             else:
#                 all_stats[tech.id] = {"count": 0, "severity": "none", "lastSeen": None}

#         return all_stats

#     except Exception as e:
#         # ส่งคืน Error ที่มีความหมายมากขึ้นสำหรับ Debug
#         raise HTTPException(status_code=500, detail=f"Error in technique-stats (XSIAM method): {str(e)}")


# --- Fix 3: Update technique-stats endpoint to use dateRange ---
# @app.post("/api/technique-stats-date", summary="Get statistics for multiple MITRE techniques")
# async def get_technique_stats(request: MitreStatsRequest):
#     """
#     Receives an index and a list of MITRE techniques, then fetches
#     detection statistics for each from Elasticsearch in a single batch request.
#     """
#     try:
#         # Default to last 7 days if no date range provided
#         if request.dateRange:
#             start_date = request.dateRange.start
#             end_date = request.dateRange.end
#         else:
#             start_date = "now-7d"
#             end_date = "now"

#         searches = []
#         # สร้าง Multi-Search (msearch) body
#         for tech in request.techniques:
#             if tech.eventIds:
#                 # ส่วน Header ของ msearch
#                 searches.append({"index": request.esIndex})
#                 # ส่วน Body (Query) ของ msearch
#                 searches.append({
#                     "query": {
#                         "bool": {
#                             "must": [
#                                 {"terms": {"event.code": tech.eventIds}},
#                                 {"range": {
#                                     "@timestamp": {
#                                         "gte": start_date,
#                                         "lte": end_date
#                                     }
#                                 }}
#                             ]
#                         }
#                     },
#                     "size": 0,
#                     "aggs": {
#                         "latest": {"max": {"field": "@timestamp"}}
#                     }
#                 })

#         # ถ้าไม่มีเทคนิคที่ต้อง query ก็คืนค่าว่างกลับไป
#         if not searches:
#             return {tech.id: {"count": 0, "severity": "none", "lastSeen": None} for tech in request.techniques}

#         # ใช้ msearch (Multi-Search) ของ Elasticsearch
#         response = await es.msearch(body=searches)

#         # ประมวลผลผลลัพธ์จาก msearch
#         all_stats = {}
#         tech_index = 0
#         for tech in request.techniques:
#             if not tech.eventIds:
#                 all_stats[tech.id] = {"count": 0, "severity": "none", "lastSeen": None}
#                 continue

#             # ดึงผลลัพธ์ที่ตรงกับเทคนิคนี้
#             result = response['responses'][tech_index]
#             tech_index += 1

#             if result.get("error"):
#                 all_stats[tech.id] = {"count": 0, "severity": "error", "lastSeen": None, "details": result["error"]}
#                 continue

#             count = result.get("hits", {}).get("total", {}).get("value", 0)
#             severity = 'critical' if count > 70 else 'high' if count > 40 else 'medium' if count > 10 else 'low' if count > 0 else 'none'
#             last_seen = result.get("aggregations", {}).get("latest", {}).get("value_as_string")

#             all_stats[tech.id] = {
#                 "count": count,
#                 "severity": severity,
#                 "lastSeen": last_seen,
#             }

#         return all_stats

#     except Exception as e:
#         import traceback
#         traceback.print_exc()
#         raise HTTPException(status_code=500, detail=f"Error in technique-stats: {str(e)}")

# ✅ แก้ไข /api/technique-stats endpoint
@app.post("/api/technique-stats")
async def get_technique_stats(request: MitreStatsRequest):
    """
    Get statistics for multiple MITRE techniques in a single request
    """
    try:
        # สร้าง date range filter
        if request.dateRange:
            start_date = request.dateRange.start
            end_date = request.dateRange.end
        else:
            # Default: last 7 days
            start_date = "now-7d"
            end_date = "now"

        # สร้าง msearch queries สำหรับทุก technique
        searches = []
        for tech in request.techniques:
            if not tech.eventIds:
                continue
                
            searches.append({"index": request.esIndex})
            searches.append({
                "query": {
                    "bool": {
                        "must": [
                            {"terms": {"event.code": tech.eventIds}},
                            {"range": {
                                "@timestamp": {
                                    "gte": start_date,
                                    "lte": end_date
                                }
                            }}
                        ]
                    }
                },
                "size": 0,
                "aggs": {
                    "latest": {
                        "max": {
                            "field": "@timestamp"
                        }
                    }
                }
            })

        # ถ้าไม่มีเทคนิคที่ต้อง query ก็คืนค่าว่างกลับไป
        if not searches:
            return {tech.id: {"count": 0, "severity": "none", "lastSeen": None} for tech in request.techniques}

        # ใช้ msearch (Multi-Search) ของ Elasticsearch
        response = await es.msearch(body=searches)

        # ประมวลผลผลลัพธ์จาก msearch
        all_stats = {}
        tech_index = 0
        for tech in request.techniques:
            if not tech.eventIds:
                all_stats[tech.id] = {"count": 0, "severity": "none", "lastSeen": None}
                continue

            # ดึงผลลัพธ์ที่ตรงกับเทคนิคนี้
            result = response['responses'][tech_index]
            tech_index += 1

            if result.get("error"):
                all_stats[tech.id] = {"count": 0, "severity": "error", "lastSeen": None, "details": result["error"]}
                continue

            count = result.get("hits", {}).get("total", {}).get("value", 0)
            
            # ✅ ใหม่: คำนวณ severity จาก EVENT_SEVERITY_MAP แทนที่จะใช้ count
            if count > 0:
                severity = calculate_technique_severity(tech.eventIds)
            else:
                severity = 'none'
            
            # ❌ เดิม: คำนวณจาก count (ผิด!)
            # severity = 'critical' if count > 70 else 'high' if count > 40 else 'medium' if count > 10 else 'low' if count > 0 else 'none'
            
            last_seen = result.get("aggregations", {}).get("latest", {}).get("value_as_string")

            all_stats[tech.id] = {
                "count": count,
                "severity": severity,
                "lastSeen": last_seen,
            }

        return all_stats

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error in technique-stats: {str(e)}")
    
@app.post("/api/technique-stats-date", summary="Get statistics for multiple MITRE techniques")
async def get_technique_stats(request: MitreStatsRequest):
    """
    Receives an index and a list of MITRE techniques, then fetches
    detection statistics for each from Elasticsearch in a single batch request.
    
    ✅ รองรับ dateRange จาก request
    ✅ คำนวณ severity จาก EVENT_SEVERITY_MAP
    """
    try:
        # ✅ ใช้ dateRange จาก request (ถ้ามี)
        if request.dateRange:
            start_date = request.dateRange.start
            end_date = request.dateRange.end
        else:
            # Default: 7 วันล่าสุด
            start_date = "now-7d"
            end_date = "now"

        searches = []
        # สร้าง Multi-Search (msearch) body
        for tech in request.techniques:
            if tech.eventIds:
                # ส่วน Header ของ msearch
                searches.append({"index": request.esIndex})
                
                # ส่วน Body (Query) ของ msearch
                searches.append({
                    "query": {
                        "bool": {
                            "must": [
                                {"terms": {"event.code": tech.eventIds}},
                                {"exists": {"field": "palo-xsiam.mitre_technique_id_and_name.keyword"}},
                                {"range": {
                                    "@timestamp": {
                                        "gte": start_date,  # ✅ ใช้ค่าจาก request
                                        "lte": end_date     # ✅ ใช้ค่าจาก request
                                    }
                                }}
                            ]
                        }
                    },
                    "size": 0,  # ไม่ต้องการผลลัพธ์, เอาแค่ count
                    "aggs": {
                        "latest": {"max": {"field": "@timestamp"}}
                    }
                })

        # ถ้าไม่มีเทคนิคที่ต้อง query ก็คืนค่าว่างกลับไป
        if not searches:
            return {tech.id: {"count": 0, "severity": "none", "lastSeen": None} for tech in request.techniques}

        # ใช้ msearch (Multi-Search) ของ Elasticsearch
        response = await es.msearch(body=searches)

        # ประมวลผลผลลัพธ์จาก msearch
        all_stats = {}
        tech_index = 0
        
        for tech in request.techniques:
            if not tech.eventIds:
                all_stats[tech.id] = {"count": 0, "severity": "none", "lastSeen": None}
                continue

            # ดึงผลลัพธ์ที่ตรงกับเทคนิคนี้
            result = response['responses'][tech_index]
            tech_index += 1

            if result.get("error"):
                all_stats[tech.id] = {
                    "count": 0,
                    "severity": "error",
                    "lastSeen": None,
                    "details": result["error"]
                }
                continue

            # ดึงจำนวน events ที่พบ
            count = result.get("hits", {}).get("total", {}).get("value", 0)
            
            # ✅ คำนวณ severity จาก event codes แทนการคำนวณจาก count
            if count > 0:
                severity = get_technique_severity(tech.eventIds)
            else:
                severity = "none"
            
            # ดึงเวลาล่าสุดที่เจอ event
            last_seen = result.get("aggregations", {}).get("latest", {}).get("value_as_string")

            all_stats[tech.id] = {
                "count": count,
                "severity": severity,
                "lastSeen": last_seen,
            }

        return all_stats

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error in technique-stats: {str(e)}")
    

# @app.post("/api/stats-date")
# async def get_statistics(
#     index: str = Query(..., description="Elasticsearch index pattern"),
#     request: StatsRequest = StatsRequest()
# ):
#     try:
#         query = {"bool": {"must": [], "filter": []}}

#         # ✅ เพิ่ม date range filter ตาม dayRange ที่ส่งมา
#         if request.dayRange:
#             query["bool"]["filter"].append({
#                 "range": {
#                     "@timestamp": {
#                         "gte": f"now-{request.dayRange}d",
#                         "lte": "now"
#                     }
#                 }
#             })

#         # ... ส่วนอื่นๆ ของ query (search, tactic, severity)
        
#         if request.search:
#             query["bool"]["must"].append({
#                 "multi_match": {
#                     "query": request.search,
#                     "fields": ["message", "host.name", "user.name", "winlog.event_data.*"],
#                     "fuzziness": "AUTO"
#                 }
#             })

#         if request.tactic and request.tactic != "all":
#             event_codes_for_tactic = [code for code, tac in EVENT_TACTIC_MAP.items() if tac == request.tactic]
#             if event_codes_for_tactic:
#                  query["bool"]["filter"].append({"terms": {"event.code": event_codes_for_tactic}})

#         if request.severity and request.severity != "all":
#             event_codes_for_severity = [code for code, info in EVENT_SEVERITY_MAP.items() if info["severity"] == request.severity]
#             if event_codes_for_severity:
#                 query["bool"]["filter"].append({"terms": {"event.code": event_codes_for_severity}})

#         # สร้าง Aggregations Query
#         aggs = {
#             "severity_counts": {
#                 "terms": {
#                     "script": {
#                         "source": """
#                             String eventCode = doc['event.code'].value;
#                             if (params.severity_map.containsKey(eventCode)) {
#                                 return params.severity_map[eventCode];
#                             }
#                             return 'unknown';
#                         """,
#                         "params": {
#                             "severity_map": {code: info["severity"] for code, info in EVENT_SEVERITY_MAP.items()}
#                         }
#                     },
#                     "size": 10
#                 }
#             },
#             "tactic_counts": {
#                  "cardinality": {
#                     "script": {
#                          "source": """
#                             String eventCode = doc['event.code'].value;
#                             if (params.tactic_map.containsKey(eventCode)) {
#                                 return params.tactic_map[eventCode];
#                             }
#                             return 'Discovery';
#                         """,
#                         "params": {
#                             "tactic_map": EVENT_TACTIC_MAP
#                         }
#                     }
#                  }
#             }
#         }

#         # ส่ง Request ไปยัง Elasticsearch
#         response = await es.search(
#             index=index,
#             body={
#                 "query": query if query["bool"]["must"] or query["bool"]["filter"] else {"match_all": {}},
#                 "size": 0,
#                 "aggs": aggs
#             }
#         )

#         # แปลงผลลัพธ์
#         aggs_result = response["aggregations"]
#         severity_buckets = aggs_result.get("severity_counts", {}).get("buckets", [])
        
#         stats_data = {
#             "total": response["hits"]["total"]["value"],
#             "critical": next((b["doc_count"] for b in severity_buckets if b["key"] == "critical"), 0),
#             "high": next((b["doc_count"] for b in severity_buckets if b["key"] == "high"), 0),
#             "medium": next((b["doc_count"] for b in severity_buckets if b["key"] == "medium"), 0),
#             "low": next((b["doc_count"] for b in severity_buckets if b["key"] == "low"), 0),
#             "tactics": aggs_result.get("tactic_counts", {}).get("value", 0)
#         }

#         return stats_data

#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))

# @app.post("/api/stats-date")
# async def get_statistics(request: MitreStatsRequest):
#     try:
#         query = {
#             "bool": {
#                 "filter": []
#             }
#         }

#         # ✅ ใช้ date range จาก React
#         if request.dateRange:
#             query["bool"]["filter"].append({
#                 "range": {
#                     "@timestamp": {
#                         "gte": request.dateRange.start,
#                         "lte": request.dateRange.end
#                     }
#                 }
#             })

#         # ✅ รวม event IDs ทั้งหมดจาก techniques ที่ React ส่งมา
#         all_event_ids = list(set(
#             event_id
#             for t in request.techniques
#             for event_id in t.eventIds
#         ))

#         if all_event_ids:
#             query["bool"]["filter"].append({"terms": {"event.code": all_event_ids}})

#         # สร้าง Aggregations Query สำหรับ Severity และ Tactic
#         aggs = {
#             "severity_counts": {
#                 "terms": {
#                     "script": {
#                         "source": """
#                             String code = doc['event.code'].value.toString();
#                             if (params.map.containsKey(code)) return params.map[code];
#                             return 'none';
#                         """,
#                         "params": {
#                             "map": {str(k): v["severity"] for k, v in EVENT_SEVERITY_MAP.items()}
#                         }
#                     },
#                     "size": 10
#                 }
#             },
#             "tactic_counts": {
#                 "cardinality": {
#                     "script": {
#                         "source": """
#                             String code = doc['event.code'].value.toString();
#                             if (params.tactic_map.containsKey(code)) {
#                                 return params.tactic_map[code];
#                             }
#                             return 'Discovery';
#                         """,
#                         "params": {
#                             "tactic_map": EVENT_TACTIC_MAP
#                         }
#                     }
#                 }
#             }
#         }

#         # ส่ง Request ไปยัง Elasticsearch
#         response = await es.search(index=request.esIndex, body={
#             "query": query if query["bool"]["must"] or query["bool"]["filter"] else {"match_all": {}},
#             "size": 0,
#             "aggs": aggs
#         })

#         # แปลงผลลัพธ์
#         aggs_result = response["aggregations"]
#         severity_buckets = aggs_result.get("severity_counts", {}).get("buckets", [])
        
#         stats_data = {
#             "total": response["hits"]["total"]["value"],
#             "critical": next((b["doc_count"] for b in severity_buckets if b["key"] == "critical"), 0),
#             "high": next((b["doc_count"] for b in severity_buckets if b["key"] == "high"), 0),
#             "medium": next((b["doc_count"] for b in severity_buckets if b["key"] == "medium"), 0),
#             "low": next((b["doc_count"] for b in severity_buckets if b["key"] == "low"), 0),
#             "tactics": aggs_result.get("tactic_counts", {}).get("value", 0)
#         }

#         return stats_data

#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/stats-date")
async def get_statistics(
    index: str = Query(..., description="Elasticsearch index pattern"),
    request: StatsRequest = StatsRequest()
):
    try:
        query = {"bool": {"must": [], "filter": []}}

        # ✅ Filter date range
        if request.dayRange:
            query["bool"]["filter"].append({
                "range": {
                    "@timestamp": {"gte": f"now-{request.dayRange}d", "lte": "now"}
                }
            })

        # ✅ Search text
        if request.search:
            query["bool"]["must"].append({
                "multi_match": {
                    "query": request.search,
                    "fields": ["message", "host.name", "user.name", "winlog.event_data.*"],
                    "fuzziness": "AUTO"
                }
            })

        # ✅ Dynamic mapping จาก React (ถ้ามีส่ง techniques มาด้วย)
        dynamic_tactic_map = {}
        if request.techniques:
            for tech in request.techniques:
                for eid in tech.eventIds:
                    dynamic_tactic_map[str(eid)] = tech.id

        # ✅ ถ้า React ไม่ได้ส่ง techniques มา → fallback ไปใช้ของเดิม
        tactic_map = dynamic_tactic_map if dynamic_tactic_map else EVENT_TACTIC_MAP

        # ✅ Filter tactic (จาก query param)
        if request.tactic and request.tactic != "all":
            event_codes_for_tactic = [code for code, tac in tactic_map.items() if tac == request.tactic]
            if event_codes_for_tactic:
                query["bool"]["filter"].append({"terms": {"event.code": event_codes_for_tactic}})

        # ✅ Filter severity (ใช้ map เดิมได้เลย)
        if request.severity and request.severity != "all":
            event_codes_for_severity = [
                code for code, info in EVENT_SEVERITY_MAP.items()
                if info["severity"] == request.severity
            ]
            if event_codes_for_severity:
                query["bool"]["filter"].append({"terms": {"event.code": event_codes_for_severity}})

        # ✅ Aggregations
        aggs = {
            "severity_counts": {
                "terms": {
                    "script": {
                        "source": """
                            String eventCode = doc['event.code'].value;
                            if (params.severity_map.containsKey(eventCode)) {
                                return params.severity_map[eventCode];
                            }
                            return 'unknown';
                        """,
                        "params": {
                            "severity_map": {code: info["severity"] for code, info in EVENT_SEVERITY_MAP.items()}
                        }
                    },
                    "size": 10
                }
            },
            "tactic_counts": {
                "terms": {  # ✅ เปลี่ยนจาก cardinality → terms เพื่อให้นับทุก tactic ได้
                    "script": {
                        "source": """
                            String eventCode = doc['event.code'].value;
                            if (params.tactic_map.containsKey(eventCode)) {
                                return params.tactic_map[eventCode];
                            }
                            return 'Unknown';
                        """,
                        "params": {"tactic_map": tactic_map}
                    },
                    "size": 50
                }
            }
        }

        # ✅ Query Elasticsearch
        response = await es.search(
            index=index,
            body={
                "query": query if query["bool"]["must"] or query["bool"]["filter"] else {"match_all": {}},
                "size": 0,
                "aggs": aggs
            }
        )

        # ✅ สรุปผลลัพธ์
        aggs_result = response["aggregations"]
        severity_buckets = aggs_result.get("severity_counts", {}).get("buckets", [])
        tactic_buckets = aggs_result.get("tactic_counts", {}).get("buckets", [])

        stats_data = {
            "total": response["hits"]["total"]["value"],
            "critical": next((b["doc_count"] for b in severity_buckets if b["key"] == "critical"), 0),
            "high": next((b["doc_count"] for b in severity_buckets if b["key"] == "high"), 0),
            "medium": next((b["doc_count"] for b in severity_buckets if b["key"] == "medium"), 0),
            "low": next((b["doc_count"] for b in severity_buckets if b["key"] == "low"), 0),
            "tactics": [
                {"name": b["key"], "count": b["doc_count"]}
                for b in tactic_buckets
            ]
        }

        return stats_data

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Endpoint สำหรับทดสอบว่า Server ทำงานหรือไม่
@app.get("/")
def read_root():
    return {"message": "MITRE Dashboard Backend is running"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)