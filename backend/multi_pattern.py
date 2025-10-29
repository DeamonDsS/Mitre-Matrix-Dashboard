# multi_pattern.py
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
import json
from pathlib import Path

load_dotenv()

es = None  # Global variable

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    global es
    ES_URL = os.getenv("ES_URL", "http://localhost:9200")
    ES_USER = os.getenv("ES_USER", "")
    ES_PASS = os.getenv("ES_PASS", "")
    # ES_INDEX = os.getenv('ES_INDEX_NAME', '.ds-winlogbeats-9.1.5-*')
    
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

# Pydantic Models
class SearchRequest(BaseModel):
    search: Optional[str] = None
    tactic: Optional[str] = "all"
    severity: Optional[str] = "all"
    size: Optional[int] = 10
    page: Optional[int] = 1

class Technique(BaseModel):
    id: str
    eventIds: List[int]

class StatsRequest(BaseModel):
    search: Optional[str] = None
    tactic: Optional[str] = "all"
    severity: Optional[str] = "all"
    dayRange: Optional[int] = 7
    techniques: Optional[List[Technique]] = []

class DateRange(BaseModel):
    start: str
    end: str

class MitreStatsRequest(BaseModel):
    esIndex: str
    techniques: List[Technique]
    dateRange: Optional[DateRange] = None

class MultiIndexStatsRequest(BaseModel):
    """Request for multi-index statistics"""
    search: Optional[str] = None
    tactic: Optional[str] = "all"
    severity: Optional[str] = "all"
    dayRange: Optional[int] = 7
    indexPattern: str  # e.g., "palo-xsiam-*" or "crowdstrike-*"

class MultiIndexTechniqueRequest(BaseModel):
    """Request for multi-index technique statistics"""
    esIndex: str
    techniques: List[Technique]
    dateRange: Optional[DateRange] = None
    indexPattern: str  # Determines which field mapping to use

# ===================================
# Legacy Event Mappings (สำหรับ Windows Events)
# NOTE: Keep these to guarantee legacy endpoints behave the same.
# ===================================

EVENT_SEVERITY_MAP = {
    "4688": {"severity": "low", "description": "Process Creation"},
    "4689": {"severity": "low", "description": "Process Termination"},
    "4624": {"severity": "low", "description": "Successful Logon"},
    "4625": {"severity": "medium", "description": "Failed Logon"},
    "4672": {"severity": "high", "description": "Special Privileges Assigned"},
    "4720": {"severity": "medium", "description": "User Account Created"},
    "4732": {"severity": "medium", "description": "Member Added to Security Group"},
    "4719": {"severity": "high", "description": "System Audit Policy Changed"},
    "4698": {"severity": "medium", "description": "Scheduled Task Created"},
    "4663": {"severity": "medium", "description": "File Access Attempt"},
    "5140": {"severity": "low", "description": "Network Share Accessed"},
    "5145": {"severity": "medium", "description": "Network Share Object Accessed"},
}

EVENT_TACTIC_MAP = {
    "4688": "TA0002",  # Execution
    "4689": "TA0002",  # Execution
    "4624": "TA0001",  # Initial Access
    "4625": "TA0006",  # Credential Access
    "4672": "TA0004",  # Privilege Escalation
    "4720": "TA0003",  # Persistence
    "4732": "TA0003",  # Persistence
    "4719": "TA0005",  # Defense Evasion
    "4698": "TA0003",  # Persistence
    "4663": "TA0009",  # Collection
    "5140": "TA0008",  # Lateral Movement
    "5145": "TA0009",  # Collection
}

def get_technique_severity(event_ids: List[int]) -> str:
    """Calculate severity based on hardcoded event codes (legacy behavior)."""
    severities = []
    for eid in event_ids:
        event_info = EVENT_SEVERITY_MAP.get(str(eid))
        if event_info:
            severities.append(event_info["severity"])
    
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

# ===================================
# Dynamic MITRE Mapping Loader (from enterprise-attack.json)
# Keep the original path as requested
# ===================================
MAPPING_PATH = Path(__file__).parent / "../frontend/public/data/enterprise-attack.json"
MITRE_MAPPING = {}
TACTIC_MAP: Dict[str, str] = {}       # TA0001 -> "Initial Access"
TECHNIQUE_MAP: Dict[str, Dict] = {}   # T1059 -> {"name": "...", "tactics": ["TA0002"], "is_subtechnique": False}

def build_dynamic_mappings(mitre_data: Dict[str, Any]):
    """
    Build mappings dynamically from MITRE enterprise-attack.json
    Produces:
      - TACTIC_MAP: tactic_id -> tactic_name
      - TECHNIQUE_MAP: technique_id -> { name, tactics: [tactic_ids], is_subtechnique }
    """
    tactic_name_to_id: Dict[str, str] = {}
    tactic_id_to_name: Dict[str, str] = {}
    technique_map: Dict[str, Dict] = {}

    objects = mitre_data.get("objects", []) if isinstance(mitre_data, dict) else []

    # First pass: tactics
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic":
            external = next(
                (ref for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"),
                None
            )
            if external and external.get("external_id"):
                tid = external["external_id"]
                tname = obj.get("name")
                tactic_name_to_id[tname] = tid
                tactic_id_to_name[tid] = tname

    # Second pass: techniques (attack-pattern)
    for obj in objects:
        if obj.get("type") == "attack-pattern":
            external = next(
                (ref for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"),
                None
            )
            if not external:
                continue
            technique_id = external.get("external_id")
            technique_name = obj.get("name")
            is_sub = obj.get("x_mitre_is_subtechnique", False)
            # kill_chain_phases gives phase_name, map that to tactic ids using tactic_name_to_id heuristics
            kill_chain_phases = obj.get("kill_chain_phases", []) or []
            tactic_ids = []
            for phase in kill_chain_phases:
                phase_name = phase.get("phase_name")
                if not phase_name:
                    continue
                # try direct match by tactic name (case-insensitive)
                for tname, tid in tactic_name_to_id.items():
                    if phase_name.lower() == tname.lower() or phase_name.lower() in tname.lower() or tname.lower() in phase_name.lower():
                        tactic_ids.append(tid)
                # if no match found, leave tactic mapping to be empty; caller can interpret as Unknown

            technique_map[technique_id] = {
                "name": technique_name,
                "tactics": tactic_ids or [],
                "is_subtechnique": bool(is_sub)
            }

    return tactic_id_to_name, technique_map

# Load MITRE JSON and build maps
try:
    with open(MAPPING_PATH, "r", encoding="utf-8") as f:
        MITRE_MAPPING = json.load(f)
    TACTIC_MAP, TECHNIQUE_MAP = build_dynamic_mappings(MITRE_MAPPING)
    print(f"✅ Loaded MITRE mapping: {len(TACTIC_MAP)} tactics, {len(TECHNIQUE_MAP)} techniques")
except FileNotFoundError:
    print(f"⚠️ enterprise-attack.json not found at {MAPPING_PATH}. Dynamic MITRE mapping disabled.")
except Exception as e:
    print(f"⚠️ Error loading MITRE mapping: {e}")

# Helper functions for other parts of app to use
def get_technique_name(tid: str) -> Optional[str]:
    """Return technique name for TID (e.g., T1059) if present in TECHNIQUE_MAP."""
    return TECHNIQUE_MAP.get(tid, {}).get("name")

def get_technique_tactics(tid: str) -> List[str]:
    """Return tactic IDs associated with a technique (may be empty)."""
    return TECHNIQUE_MAP.get(tid, {}).get("tactics", [])

def get_tactic_name(tid: str) -> Optional[str]:
    """Return tactic name for TA id (e.g., TA0002)."""
    return TACTIC_MAP.get(tid)

# ===================================
# Field mappings for different index patterns (unchanged)
# ===================================
INDEX_FIELD_MAPPINGS = {
    "palo-xsiam": {
        "tactic_field": "palo-xsiam.mitre_tactic_id_and_name.keyword",
        "technique_field": "palo-xsiam.mitre_technique_id_and_name.keyword",
        "category_field": "palo-xsiam.category.keyword",
        "timestamp_field": "@timestamp",
        "tactic_parser": lambda val: val.split(" - ")[0] if " - " in val else val,  # "TA0040 - Impact" -> "TA0040"
        "technique_parser": lambda val: val.split(" - ")[0] if " - " in val else val,  # "T1491 - Defacement" -> "T1491"
    },
    "crowdstrike": {
        "tactic_field": "crowdstrike.event.MitreAttack.Tactic.keyword",
        "tactic_id_field": "crowdstrike.event.MitreAttack.TacticID.keyword",
        "technique_field": "crowdstrike.event.MitreAttack.Technique.keyword",
        "technique_id_field": "crowdstrike.event.MitreAttack.TechniqueID.keyword",
        "timestamp_field": "@timestamp",
        "tactic_parser": lambda val: val,  # "Impact" as is
        "technique_parser": lambda val: val,  # "Inhibit System Recovery" as is
    }
}

def get_field_mapping(index_pattern: str) -> Dict:
    """Determine field mapping based on index pattern"""
    index_lower = index_pattern.lower()
    
    if "palo-xsiam" in index_lower or "palo" in index_lower:
        return INDEX_FIELD_MAPPINGS["palo-xsiam"]
    elif "crowdstrike" in index_lower:
        return INDEX_FIELD_MAPPINGS["crowdstrike"]
    elif "windows" in index_lower or "winlog" in index_lower:
        # Windows pattern detected - should use legacy endpoint instead
        raise ValueError(
            f"Windows index pattern detected: {index_pattern}. "
            "Please use legacy endpoints (/api/technique-stats-date, /api/stats-date) for Windows event logs."
        )
    else:
        raise ValueError(
            f"Unsupported index pattern: {index_pattern}. "
            "Supported patterns: palo-xsiam, crowdstrike"
        )

def build_technique_query(field_mapping: Dict, technique_ids: List[str], start_date: str, end_date: str) -> Dict:
    """Build query for technique detection based on index type"""
    
    if "technique_id_field" in field_mapping:
        # CrowdStrike: has separate ID field
        return {
            "query": {
                "bool": {
                    "must": [
                        {"terms": {field_mapping["technique_id_field"]: technique_ids}},
                        {"range": {
                            field_mapping["timestamp_field"]: {
                                "gte": start_date,
                                "lte": end_date
                            }
                        }}
                    ]
                }
            },
            "size": 0,
            "aggs": {
                "latest": {"max": {"field": field_mapping["timestamp_field"]}}
            }
        }
    else:
        # Palo Alto: ID is part of the combined field
        # Match patterns like "T1491 - Defacement"
        # Use wildcard for each technique id (Elasticsearch wildcard accepts single pattern, we'll combine using bool/should where caller needs)
        technique_patterns = [f"{tid} - *" for tid in technique_ids]
        # If only one technique pattern, keep it simple
        if len(technique_patterns) == 1:
            wildcard_clause = {"wildcard": {field_mapping["technique_field"]: {"value": technique_patterns[0]}}}
        else:
            wildcard_clause = {
                "bool": {
                    "should": [
                        {"wildcard": {field_mapping["technique_field"]: {"value": pat}}} for pat in technique_patterns
                    ]
                }
            }
        return {
            "query": {
                "bool": {
                    "must": [
                        wildcard_clause,
                        {"range": {
                            field_mapping["timestamp_field"]: {
                                "gte": start_date,
                                "lte": end_date
                            }
                        }}
                    ]
                }
            },
            "size": 0,
            "aggs": {
                "latest": {"max": {"field": field_mapping["timestamp_field"]}}
            }
        }
    
# ===================================
# Legacy Endpoints (Windows-focused) - kept intact
# ===================================

@app.post("/api/technique-stats-date", summary="Get statistics for multiple MITRE techniques (Legacy)")
async def get_technique_stats(request: MitreStatsRequest):
    """
    Legacy endpoint for Windows event logs.
    Uses event.code field for detection.
    
    ✅ รองรับ dateRange จาก request
    ✅ คำนวณ severity จาก EVENT_SEVERITY_MAP
    """
    try:
        # ใช้ dateRange จาก request (ถ้ามี)
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
            
            # คำนวณ severity จาก event codes (legacy)
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


@app.post("/api/stats-date", summary="Get overall statistics (Legacy)")
async def get_statistics(
    index: str = Query(..., description="Elasticsearch index pattern"),
    request: StatsRequest = StatsRequest()
):
    """
    Legacy endpoint for Windows event logs statistics.
    Returns counts by severity and tactic.
    """
    try:
        query = {"bool": {"must": [], "filter": []}}

        # Filter date range
        if request.dayRange:
            query["bool"]["filter"].append({
                "range": {
                    "@timestamp": {"gte": f"now-{request.dayRange}d", "lte": "now"}
                }
            })

        # Search text
        if request.search:
            query["bool"]["must"].append({
                "multi_match": {
                    "query": request.search,
                    "fields": ["message", "host.name", "user.name", "winlog.event_data.*"],
                    "fuzziness": "AUTO"
                }
            })

        # Dynamic mapping จาก React (ถ้ามีส่ง techniques มาด้วย)
        dynamic_tactic_map = {}
        if request.techniques:
            for tech in request.techniques:
                for eid in tech.eventIds:
                    dynamic_tactic_map[str(eid)] = tech.id

        # ถ้า React ไม่ได้ส่ง techniques มา → fallback ไปใช้ของเดิม
        tactic_map = dynamic_tactic_map if dynamic_tactic_map else EVENT_TACTIC_MAP

        # Filter tactic (จาก query param)
        if request.tactic and request.tactic != "all":
            event_codes_for_tactic = [code for code, tac in tactic_map.items() if tac == request.tactic]
            if event_codes_for_tactic:
                query["bool"]["filter"].append({"terms": {"event.code": event_codes_for_tactic}})

        # Filter severity (ใช้ map เดิมได้เลย)
        if request.severity and request.severity != "all":
            event_codes_for_severity = [
                code for code, info in EVENT_SEVERITY_MAP.items()
                if info["severity"] == request.severity
            ]
            if event_codes_for_severity:
                query["bool"]["filter"].append({"terms": {"event.code": event_codes_for_severity}})

        # Aggregations
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
                "terms": {
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

        # Query Elasticsearch
        response = await es.search(
            index=index,
            body={
                "query": query if query["bool"]["must"] or query["bool"]["filter"] else {"match_all": {}},
                "size": 0,
                "aggs": aggs
            }
        )

        # สรุปผลลัพธ์
        aggs_result = response["aggregations"]
        severity_buckets = aggs_result.get("severity_counts", {}).get("buckets", [])
        tactic_buckets = aggs_result.get("tactic_counts", {}).get("buckets", [])

        stats_data = {
            "total": response["hits"]["total"]["value"],
            "critical": next((b["doc_count"] for b in severity_buckets if b["key"] == "critical"), 0),
            "high": next((b["doc_count"] for b in severity_buckets if b["key"] == "high"), 0),
            "medium": next((b["doc_count"] for b in severity_buckets if b["key"] == "medium"), 0),
            "low": next((b["doc_count"] for b in severity_buckets if b["key"] == "low"), 0),
            "tactics": len(tactic_buckets)  # ส่งกลับเป็น count (legacy format)
        }

        return stats_data

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
        
# ===================================
# Multi-index endpoints (unchanged behavior — as requested)
# ===================================

@app.post("/api/multi-index/technique-stats", summary="Get statistics for MITRE techniques across different index patterns")
async def get_multi_index_technique_stats(request: MultiIndexTechniqueRequest):
    """
    Universal endpoint that works with different index patterns:
    - palo-xsiam-*: Uses palo-xsiam.mitre_technique_id_and_name
    - crowdstrike-*: Uses crowdstrike.event.MitreAttack.TechniqueID
    
    Automatically detects index pattern and uses appropriate fields.
    """
    try:
        # Check if this is a Windows index pattern
        if "windows" in request.indexPattern.lower() or "winlog" in request.indexPattern.lower():
            raise HTTPException(
                status_code=400,
                detail="Windows event logs are not supported by multi-index endpoints. Please use /api/stats-date endpoint instead."
            )
        # Get field mapping for this index pattern
        field_mapping = get_field_mapping(request.indexPattern)
        
        # Determine date range
        if request.dateRange:
            start_date = request.dateRange.start
            end_date = request.dateRange.end
        else:
            start_date = "now-7d"
            end_date = "now"

        searches = []
        
        # Build multi-search queries
        for tech in request.techniques:
            # Extract technique IDs from the tech object
            # Assuming tech.id is like "T1491" or contains technique ID
            technique_ids = [tech.id] if isinstance(tech.id, str) and tech.id.upper().startswith("T") else []
            
            if not technique_ids:
                continue
                
            # Header for msearch
            searches.append({"index": request.esIndex})
            
            # Query body based on index type
            if "technique_id_field" in field_mapping:
                # CrowdStrike-style: separate ID field
                searches.append({
                    "query": {
                        "bool": {
                            "must": [
                                {"terms": {field_mapping["technique_id_field"]: technique_ids}},
                                {"range": {
                                    field_mapping["timestamp_field"]: {
                                        "gte": start_date,
                                        "lte": end_date
                                    }
                                }}
                            ]
                        }
                    },
                    "size": 0,
                    "aggs": {
                        "latest": {"max": {"field": field_mapping["timestamp_field"]}}
                    }
                })
            else:
                # Palo Alto-style: combined field with pattern
                searches.append({
                    "query": {
                        "bool": {
                            "must": [
                                {
                                    "bool": {
                                        "should": [
                                            {"wildcard": {field_mapping["technique_field"]: f"{tid} - *"}}
                                            for tid in technique_ids
                                        ]
                                    }
                                },
                                {"range": {
                                    field_mapping["timestamp_field"]: {
                                        "gte": start_date,
                                        "lte": end_date
                                    }
                                }}
                            ]
                        }
                    },
                    "size": 0,
                    "aggs": {
                        "latest": {"max": {"field": field_mapping["timestamp_field"]}}
                    }
                })

        if not searches:
            return {tech.id: {"count": 0, "severity": "none", "lastSeen": None} for tech in request.techniques}

        # Execute multi-search
        response = await es.msearch(body=searches)

        # Process results
        all_stats = {}
        tech_index = 0
        
        for tech in request.techniques:
            technique_ids = [tech.id] if isinstance(tech.id, str) and tech.id.upper().startswith("T") else []
            
            if not technique_ids:
                all_stats[tech.id] = {"count": 0, "severity": "none", "lastSeen": None}
                continue

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

            count = result.get("hits", {}).get("total", {}).get("value", 0)
            
            # Calculate severity (you can customize this based on your logic)
            if count > 100:
                severity = "critical"
            elif count > 50:
                severity = "high"
            elif count > 10:
                severity = "medium"
            elif count > 0:
                severity = "low"
            else:
                severity = "none"
            
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
        raise HTTPException(status_code=500, detail=f"Error in multi-index technique-stats: {str(e)}")


@app.post("/api/multi-index/stats", summary="Get statistics across different index patterns")
async def get_multi_index_statistics(request: MultiIndexStatsRequest):
    """
    Universal statistics endpoint that works with:
    - palo-xsiam-*: Uses palo-xsiam.mitre_tactic_id_and_name
    - crowdstrike-*: Uses crowdstrike.event.MitreAttack.TacticID
    
    Returns aggregated counts by tactic and severity.
    """
    try:
        # Check if this is a Windows index pattern
        if "windows" in request.indexPattern.lower() or "winlog" in request.indexPattern.lower():
            raise HTTPException(
                status_code=400,
                detail="Windows event logs are not supported by multi-index endpoints. Please use /api/stats-date endpoint instead."
            )
        # Get field mapping
        field_mapping = get_field_mapping(request.indexPattern)
        
        query = {"bool": {"must": [], "filter": []}}

        # Date range filter
        if request.dayRange:
            query["bool"]["filter"].append({
                "range": {
                    field_mapping["timestamp_field"]: {
                        "gte": f"now-{request.dayRange}d",
                        "lte": "now"
                    }
                }
            })

        # Search text filter
        if request.search:
            search_fields = ["message", "host.name", "user.name"]
            if "category_field" in field_mapping:
                search_fields.append(field_mapping["category_field"])
            
            query["bool"]["must"].append({
                "multi_match": {
                    "query": request.search,
                    "fields": search_fields,
                    "fuzziness": "AUTO"
                }
            })

        # Tactic filter
        if request.tactic and request.tactic != "all":
            if "tactic_id_field" in field_mapping:
                # CrowdStrike: has separate tactic ID field
                query["bool"]["filter"].append({
                    "term": {field_mapping["tactic_id_field"]: request.tactic}
                })
            else:
                # Palo Alto: combined field with pattern
                query["bool"]["filter"].append({
                    "wildcard": {field_mapping["tactic_field"]: f"{request.tactic} - *"}
                })

        # Aggregations
        aggs = {
            "tactic_counts": {
                "terms": {
                    "field": field_mapping.get("tactic_id_field", field_mapping["tactic_field"]),
                    "size": 50
                }
            }
        }
        
        # Add category aggregation for Palo Alto
        if "category_field" in field_mapping:
            aggs["category_counts"] = {
                "terms": {
                    "field": field_mapping["category_field"],
                    "size": 20
                }
            }

        # Execute query
        response = await es.search(
            index=request.indexPattern,
            body={
                "query": query if query["bool"]["must"] or query["bool"]["filter"] else {"match_all": {}},
                "size": 0,
                "aggs": aggs
            }
        )

        # Process results
        aggs_result = response["aggregations"]
        tactic_buckets = aggs_result.get("tactic_counts", {}).get("buckets", [])
        category_buckets = aggs_result.get("category_counts", {}).get("buckets", [])

        # Parse tactics based on field format
        tactics = []
        for bucket in tactic_buckets:
            tactic_value = bucket["key"]
            # Extract tactic ID if it's in combined format
            if " - " in tactic_value:
                tactic_id = tactic_value.split(" - ")[0]
            else:
                tactic_id = tactic_value
            
            tactics.append({
                "name": tactic_id,
                "count": bucket["doc_count"]
            })

        stats_data = {
            "total": response["hits"]["total"]["value"],
            "tactics": tactics,
            "categories": [
                {"name": b["key"], "count": b["doc_count"]}
                for b in category_buckets
            ] if category_buckets else []
        }

        return stats_data

    except HTTPException:
        raise  # Re-raise HTTP exceptions
    except Exception as e:
        import traceback
        traceback.print_exc()
        
        # Check if it's an index not found error
        if "index_not_found_exception" in str(e):
            raise HTTPException(
                status_code=404,
                detail=f"Index pattern not found: {request.indexPattern}. Please verify the index exists in Elasticsearch."
            )
        
        raise HTTPException(status_code=500, detail=f"Error in multi-index stats: {str(e)}")



@app.get("/api/multi-index/search", summary="Search MITRE detections across index patterns")
async def search_multi_index(
    index: str = Query(..., description="Elasticsearch index pattern"),
    search: Optional[str] = None,
    tactic: Optional[str] = "all",
    severity: Optional[str] = "all",
    size: int = 10,
    page: int = 1
):
    """
    Search endpoint that works across different index patterns.
    Automatically adapts to field names based on index pattern.
    """
    try:
        field_mapping = get_field_mapping(index)
        
        query = {"bool": {"must": [], "filter": []}}
        
        # Search filter
        if search:
            query["bool"]["must"].append({
                "multi_match": {
                    "query": search,
                    "fields": [
                        "message",
                        "host.name",
                        "user.name",
                        field_mapping["technique_field"],
                        field_mapping["tactic_field"]
                    ],
                    "fuzziness": "AUTO"
                }
            })
        
        # Tactic filter
        if tactic and tactic != "all":
            if "tactic_id_field" in field_mapping:
                query["bool"]["filter"].append({
                    "term": {field_mapping["tactic_id_field"]: tactic}
                })
            else:
                query["bool"]["filter"].append({
                    "wildcard": {field_mapping["tactic_field"]: f"{tactic} - *"}
                })
        
        # Calculate pagination
        from_index = (page - 1) * size
        
        # Execute search
        response = await es.search(
            index=index,
            body={
                "query": query if query["bool"]["must"] or query["bool"]["filter"] else {"match_all": {}},
                "size": size,
                "from": from_index,
                "sort": [{field_mapping["timestamp_field"]: "desc"}]
            }
        )
        
        # Format results
        hits = response["hits"]["hits"]
        total = response["hits"]["total"]["value"]
        
        results = []
        for hit in hits:
            source = hit["_source"]
            
            # Extract fields based on index pattern
            if "palo-xsiam" in index.lower():
                result = {
                    "id": hit["_id"],
                    "timestamp": source.get("@timestamp"),
                    "tactic": source.get("palo-xsiam", {}).get("mitre_tactic_id_and_name"),
                    "technique": source.get("palo-xsiam", {}).get("mitre_technique_id_and_name"),
                    "category": source.get("palo-xsiam", {}).get("category"),
                    "host": source.get("host", {}).get("name"),
                    "message": source.get("message")
                }
            else:  # CrowdStrike
                mitre_attack = source.get("crowdstrike", {}).get("event", {}).get("MitreAttack", {})
                result = {
                    "id": hit["_id"],
                    "timestamp": source.get("@timestamp"),
                    "tactic": mitre_attack.get("Tactic"),
                    "tacticId": mitre_attack.get("TacticID"),
                    "technique": mitre_attack.get("Technique"),
                    "techniqueId": mitre_attack.get("TechniqueID"),
                    "host": source.get("host", {}).get("name"),
                    "message": source.get("message")
                }
            
            results.append(result)
        
        return {
            "total": total,
            "page": page,
            "size": size,
            "results": results
        }
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error in multi-index search: {str(e)}")
    
# Add these new models and endpoints to your multi_pattern.py file

# ===================================
# New Pydantic Models for Unified Endpoints
# ===================================

class UnifiedTechniqueRequest(BaseModel):
    """Request for unified technique statistics across all index patterns"""
    indices: List[str]  # List of index patterns to query (e.g., ["palo-xsiam-*", "crowdstrike-*"])
    techniques: List[Technique]
    dateRange: Optional[DateRange] = None

class UnifiedStatsRequest(BaseModel):
    """Request for unified statistics across all index patterns"""
    indices: List[str]  # List of index patterns to query
    search: Optional[str] = None
    tactic: Optional[str] = "all"
    severity: Optional[str] = "all"
    dayRange: Optional[int] = 7

class UnifiedSearchRequest(BaseModel):
    """Request for unified search across all index patterns"""
    indices: List[str]
    search: Optional[str] = None
    tactic: Optional[str] = "all"
    severity: Optional[str] = "all"
    size: Optional[int] = 10
    page: Optional[int] = 1


# ===================================
# Helper Functions for Unified Queries
# ===================================

def filter_valid_indices(indices: List[str]) -> List[str]:
    """Filter out Windows/winlog indices from the list"""
    valid_indices = []
    for idx in indices:
        idx_lower = idx.lower()
        if "windows" not in idx_lower and "winlog" not in idx_lower:
            valid_indices.append(idx)
    return valid_indices


async def validate_indices(indices: List[str]) -> Dict[str, bool]:
    """Check which indices exist in Elasticsearch"""
    valid_indices = {}
    for idx in indices:
        try:
            exists = await es.indices.exists(index=idx)
            valid_indices[idx] = exists
        except Exception as e:
            print(f"Error checking index {idx}: {e}")
            valid_indices[idx] = False
    return valid_indices


# ===================================
# Unified Endpoints (New)
# ===================================

@app.post("/api/unified/technique-stats", summary="Get technique statistics across multiple index patterns")
async def get_unified_technique_stats(request: UnifiedTechniqueRequest):
    """
    Unified endpoint that queries multiple index patterns simultaneously.
    Combines results from Palo Alto XSIAM, CrowdStrike, and other supported sources.
    
    Example request:
    {
        "indices": ["palo-xsiam-*", "crowdstrike-*"],
        "techniques": [
            {"id": "T1059", "eventIds": []},
            {"id": "T1068", "eventIds": []}
        ],
        "dateRange": {
            "start": "2024-01-01T00:00:00Z",
            "end": "2024-01-31T23:59:59Z"
        }
    }
    """
    try:
        # Filter out Windows indices
        valid_indices = filter_valid_indices(request.indices)
        
        if not valid_indices:
            raise HTTPException(
                status_code=400,
                detail="No valid indices provided. Windows/winlog indices are not supported in unified endpoints."
            )
        
        # Validate indices exist
        indices_status = await validate_indices(valid_indices)
        existing_indices = [idx for idx, exists in indices_status.items() if exists]
        
        if not existing_indices:
            raise HTTPException(
                status_code=404,
                detail=f"None of the provided indices exist: {valid_indices}"
            )
        
        # Determine date range
        if request.dateRange:
            start_date = request.dateRange.start
            end_date = request.dateRange.end
        else:
            start_date = "now-7d"
            end_date = "now"
        
        # Initialize aggregated results
        unified_stats = {}
        for tech in request.techniques:
            unified_stats[tech.id] = {
                "count": 0,
                "severity": "none",
                "lastSeen": None,
                "sources": {}  # Track counts per index pattern
            }
        
        # Query each index pattern
        for index_pattern in existing_indices:
            try:
                field_mapping = get_field_mapping(index_pattern)
                searches = []
                
                # Build multi-search for this index pattern
                for tech in request.techniques:
                    technique_ids = [tech.id] if isinstance(tech.id, str) and tech.id.upper().startswith("T") else []
                    
                    if not technique_ids:
                        continue
                    
                    searches.append({"index": index_pattern})
                    
                    # Build query based on index type
                    if "technique_id_field" in field_mapping:
                        # CrowdStrike-style
                        searches.append({
                            "query": {
                                "bool": {
                                    "must": [
                                        {"terms": {field_mapping["technique_id_field"]: technique_ids}},
                                        {"range": {
                                            field_mapping["timestamp_field"]: {
                                                "gte": start_date,
                                                "lte": end_date
                                            }
                                        }}
                                    ]
                                }
                            },
                            "size": 0,
                            "aggs": {
                                "latest": {"max": {"field": field_mapping["timestamp_field"]}}
                            }
                        })
                    else:
                        # Palo Alto-style
                        searches.append({
                            "query": {
                                "bool": {
                                    "must": [
                                        {
                                            "bool": {
                                                "should": [
                                                    {"wildcard": {field_mapping["technique_field"]: f"{tid} - *"}}
                                                    for tid in technique_ids
                                                ]
                                            }
                                        },
                                        {"range": {
                                            field_mapping["timestamp_field"]: {
                                                "gte": start_date,
                                                "lte": end_date
                                            }
                                        }}
                                    ]
                                }
                            },
                            "size": 0,
                            "aggs": {
                                "latest": {"max": {"field": field_mapping["timestamp_field"]}}
                            }
                        })
                
                if not searches:
                    continue
                
                # Execute multi-search for this index
                response = await es.msearch(body=searches)
                
                # Process results
                tech_index = 0
                for tech in request.techniques:
                    technique_ids = [tech.id] if isinstance(tech.id, str) and tech.id.upper().startswith("T") else []
                    
                    if not technique_ids:
                        continue
                    
                    result = response['responses'][tech_index]
                    tech_index += 1
                    
                    if result.get("error"):
                        print(f"Error querying {index_pattern} for {tech.id}: {result['error']}")
                        continue
                    
                    count = result.get("hits", {}).get("total", {}).get("value", 0)
                    last_seen = result.get("aggregations", {}).get("latest", {}).get("value_as_string")
                    
                    # Aggregate counts
                    unified_stats[tech.id]["count"] += count
                    unified_stats[tech.id]["sources"][index_pattern] = count
                    
                    # Update lastSeen to most recent
                    if last_seen:
                        current_last = unified_stats[tech.id]["lastSeen"]
                        if not current_last or last_seen > current_last:
                            unified_stats[tech.id]["lastSeen"] = last_seen
            
            except ValueError as ve:
                # Unsupported index pattern
                print(f"Skipping unsupported index pattern {index_pattern}: {ve}")
                continue
            except Exception as e:
                print(f"Error processing index {index_pattern}: {e}")
                continue
        
        # Calculate severity based on total counts
        for tech_id, stats in unified_stats.items():
            count = stats["count"]
            if count > 100:
                stats["severity"] = "critical"
            elif count > 50:
                stats["severity"] = "high"
            elif count > 10:
                stats["severity"] = "medium"
            elif count > 0:
                stats["severity"] = "low"
            else:
                stats["severity"] = "none"
        
        return unified_stats
    
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error in unified technique-stats: {str(e)}")


@app.post("/api/unified/stats", summary="Get overall statistics across multiple index patterns")
async def get_unified_statistics(request: UnifiedStatsRequest):
    """
    Unified statistics endpoint that aggregates data from multiple sources.
    Returns combined counts by tactic and provides breakdown by source.
    
    Example request:
    {
        "indices": ["palo-xsiam-*", "crowdstrike-*"],
        "search": "malware",
        "tactic": "TA0002",
        "dayRange": 7
    }
    """
    try:
        # Filter out Windows indices
        valid_indices = filter_valid_indices(request.indices)
        
        if not valid_indices:
            raise HTTPException(
                status_code=400,
                detail="No valid indices provided. Windows/winlog indices are not supported."
            )
        
        # Validate indices exist
        indices_status = await validate_indices(valid_indices)
        existing_indices = [idx for idx, exists in indices_status.items() if exists]
        
        if not existing_indices:
            raise HTTPException(
                status_code=404,
                detail=f"None of the provided indices exist: {valid_indices}"
            )
        
        # Initialize aggregated results
        unified_stats = {
            "total": 0,
            "tactics": {},  # tactic_id -> {name, count, sources: {index: count}}
            "sources": {},  # index -> total count
            "breakdown": []  # List of per-index stats
        }
        
        # Query each index pattern
        for index_pattern in existing_indices:
            try:
                field_mapping = get_field_mapping(index_pattern)
                query = {"bool": {"must": [], "filter": []}}
                
                # Date range filter
                if request.dayRange:
                    query["bool"]["filter"].append({
                        "range": {
                            field_mapping["timestamp_field"]: {
                                "gte": f"now-{request.dayRange}d",
                                "lte": "now"
                            }
                        }
                    })
                
                # Search filter
                if request.search:
                    search_fields = ["message", "host.name", "user.name"]
                    if "category_field" in field_mapping:
                        search_fields.append(field_mapping["category_field"])
                    
                    query["bool"]["must"].append({
                        "multi_match": {
                            "query": request.search,
                            "fields": search_fields,
                            "fuzziness": "AUTO"
                        }
                    })
                
                # Tactic filter
                if request.tactic and request.tactic != "all":
                    if "tactic_id_field" in field_mapping:
                        query["bool"]["filter"].append({
                            "term": {field_mapping["tactic_id_field"]: request.tactic}
                        })
                    else:
                        query["bool"]["filter"].append({
                            "wildcard": {field_mapping["tactic_field"]: f"{request.tactic} - *"}
                        })
                
                # Aggregations
                aggs = {
                    "tactic_counts": {
                        "terms": {
                            "field": field_mapping.get("tactic_id_field", field_mapping["tactic_field"]),
                            "size": 50
                        }
                    }
                }
                
                # Execute query
                response = await es.search(
                    index=index_pattern,
                    body={
                        "query": query if query["bool"]["must"] or query["bool"]["filter"] else {"match_all": {}},
                        "size": 0,
                        "aggs": aggs
                    }
                )
                
                # Process results
                total_for_index = response["hits"]["total"]["value"]
                unified_stats["total"] += total_for_index
                unified_stats["sources"][index_pattern] = total_for_index
                
                # Process tactic counts
                tactic_buckets = response["aggregations"].get("tactic_counts", {}).get("buckets", [])
                
                for bucket in tactic_buckets:
                    tactic_value = bucket["key"]
                    count = bucket["doc_count"]
                    
                    # Extract tactic ID
                    if " - " in tactic_value:
                        tactic_id = tactic_value.split(" - ")[0]
                        tactic_name = tactic_value.split(" - ")[1] if len(tactic_value.split(" - ")) > 1 else tactic_id
                    else:
                        tactic_id = tactic_value
                        tactic_name = get_tactic_name(tactic_id) or tactic_id
                    
                    # Aggregate tactic counts
                    if tactic_id not in unified_stats["tactics"]:
                        unified_stats["tactics"][tactic_id] = {
                            "name": tactic_name,
                            "count": 0,
                            "sources": {}
                        }
                    
                    unified_stats["tactics"][tactic_id]["count"] += count
                    unified_stats["tactics"][tactic_id]["sources"][index_pattern] = count
                
                # Add breakdown per index
                unified_stats["breakdown"].append({
                    "index": index_pattern,
                    "total": total_for_index,
                    "tactics": len(tactic_buckets)
                })
            
            except ValueError as ve:
                print(f"Skipping unsupported index pattern {index_pattern}: {ve}")
                continue
            except Exception as e:
                print(f"Error processing index {index_pattern}: {e}")
                continue
        
        # Format tactics as list
        tactics_list = [
            {
                "id": tactic_id,
                "name": data["name"],
                "count": data["count"],
                "sources": data["sources"]
            }
            for tactic_id, data in unified_stats["tactics"].items()
        ]
        
        # Sort by count descending
        tactics_list.sort(key=lambda x: x["count"], reverse=True)
        
        return {
            "total": unified_stats["total"],
            "tactics": tactics_list,
            "sources": unified_stats["sources"],
            "breakdown": unified_stats["breakdown"]
        }
    
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error in unified stats: {str(e)}")


@app.post("/api/unified/search", summary="Search across multiple index patterns")
async def search_unified(request: UnifiedSearchRequest):
    """
    Unified search endpoint that queries multiple index patterns and combines results.
    Results are sorted by timestamp across all sources.
    
    Example request:
    {
        "indices": ["palo-xsiam-*", "crowdstrike-*"],
        "search": "suspicious activity",
        "tactic": "all",
        "size": 20,
        "page": 1
    }
    """
    try:
        # Filter out Windows indices
        valid_indices = filter_valid_indices(request.indices)
        
        if not valid_indices:
            raise HTTPException(
                status_code=400,
                detail="No valid indices provided. Windows/winlog indices are not supported."
            )
        
        # Validate indices exist
        indices_status = await validate_indices(valid_indices)
        existing_indices = [idx for idx, exists in indices_status.items() if exists]
        
        if not existing_indices:
            raise HTTPException(
                status_code=404,
                detail=f"None of the provided indices exist: {valid_indices}"
            )
        
        all_results = []
        total_count = 0
        
        # Query each index pattern
        for index_pattern in existing_indices:
            try:
                field_mapping = get_field_mapping(index_pattern)
                query = {"bool": {"must": [], "filter": []}}
                
                # Search filter
                if request.search:
                    query["bool"]["must"].append({
                        "multi_match": {
                            "query": request.search,
                            "fields": [
                                "message",
                                "host.name",
                                "user.name",
                                field_mapping["technique_field"],
                                field_mapping["tactic_field"]
                            ],
                            "fuzziness": "AUTO"
                        }
                    })
                
                # Tactic filter
                if request.tactic and request.tactic != "all":
                    if "tactic_id_field" in field_mapping:
                        query["bool"]["filter"].append({
                            "term": {field_mapping["tactic_id_field"]: request.tactic}
                        })
                    else:
                        query["bool"]["filter"].append({
                            "wildcard": {field_mapping["tactic_field"]: f"{request.tactic} - *"}
                        })
                
                # Get more results than needed for proper pagination after combining
                response = await es.search(
                    index=index_pattern,
                    body={
                        "query": query if query["bool"]["must"] or query["bool"]["filter"] else {"match_all": {}},
                        "size": request.size * len(existing_indices),  # Get enough from each source
                        "sort": [{field_mapping["timestamp_field"]: "desc"}]
                    }
                )
                
                total_count += response["hits"]["total"]["value"]
                
                # Format results for this index
                for hit in response["hits"]["hits"]:
                    source = hit["_source"]
                    
                    if "palo-xsiam" in index_pattern.lower():
                        result = {
                            "id": hit["_id"],
                            "index": index_pattern,
                            "timestamp": source.get("@timestamp"),
                            "tactic": source.get("palo-xsiam", {}).get("mitre_tactic_id_and_name"),
                            "technique": source.get("palo-xsiam", {}).get("mitre_technique_id_and_name"),
                            "category": source.get("palo-xsiam", {}).get("category"),
                            "host": source.get("host", {}).get("name"),
                            "message": source.get("message")
                        }
                    else:  # CrowdStrike
                        mitre_attack = source.get("crowdstrike", {}).get("event", {}).get("MitreAttack", {})
                        result = {
                            "id": hit["_id"],
                            "index": index_pattern,
                            "timestamp": source.get("@timestamp"),
                            "tactic": mitre_attack.get("Tactic"),
                            "tacticId": mitre_attack.get("TacticID"),
                            "technique": mitre_attack.get("Technique"),
                            "techniqueId": mitre_attack.get("TechniqueID"),
                            "host": source.get("host", {}).get("name"),
                            "message": source.get("message")
                        }
                    
                    all_results.append(result)
            
            except ValueError as ve:
                print(f"Skipping unsupported index pattern {index_pattern}: {ve}")
                continue
            except Exception as e:
                print(f"Error searching index {index_pattern}: {e}")
                continue
        
        # Sort combined results by timestamp
        all_results.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        
        # Apply pagination to combined results
        from_index = (request.page - 1) * request.size
        to_index = from_index + request.size
        paginated_results = all_results[from_index:to_index]
        
        return {
            "total": total_count,
            "page": request.page,
            "size": request.size,
            "results": paginated_results,
            "sources": list(existing_indices)
        }
    
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error in unified search: {str(e)}")

# Add these models near the other Pydantic models section

class TopTechniquesRequest(BaseModel):
    """Request for top detected techniques"""
    indices: List[str]
    dayRange: Optional[int] = 7
    limit: Optional[int] = 5
    tactic: Optional[str] = "all"

class TopTechniqueResult(BaseModel):
    """Result for a single technique"""
    technique_id: str
    technique_name: str
    count: int
    tactic_ids: List[str]
    tactic_names: List[str]
    sources: Dict[str, int]  # index -> count

# Add this endpoint with the other unified endpoints

@app.post("/api/unified/top-techniques", summary="Get top N most detected techniques across indices")
async def get_top_techniques(request: TopTechniquesRequest):
    """
    Get the top N most detected MITRE techniques across multiple index patterns.
    Aggregates data from all specified indices and returns techniques ranked by detection count.
    
    Example request:
    {
        "indices": ["palo-xsiam-*", "crowdstrike-*"],
        "dayRange": 7,
        "limit": 5,
        "tactic": "all"
    }
    
    Returns:
    {
        "techniques": [
            {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "count": 1523,
                "tactic_ids": ["TA0002"],
                "tactic_names": ["Execution"],
                "sources": {"palo-xsiam-*": 1200, "crowdstrike-*": 323}
            },
            ...
        ],
        "total_detections": 5420,
        "time_range": {"start": "2024-10-20T00:00:00Z", "end": "2024-10-27T23:59:59Z"}
    }
    """
    try:
        # Filter out Windows indices
        valid_indices = filter_valid_indices(request.indices)
        
        if not valid_indices:
            raise HTTPException(
                status_code=400,
                detail="No valid indices provided. Windows/winlog indices are not supported."
            )
        
        # Validate indices exist
        indices_status = await validate_indices(valid_indices)
        existing_indices = [idx for idx, exists in indices_status.items() if exists]
        
        if not existing_indices:
            raise HTTPException(
                status_code=404,
                detail=f"None of the provided indices exist: {valid_indices}"
            )
        
        # Calculate time range
        from datetime import datetime, timedelta
        end_date = datetime.now()
        start_date = end_date - timedelta(days=request.dayRange)
        
        # Dictionary to aggregate technique counts across all indices
        technique_aggregation = {}
        total_detections = 0
        
        # Query each index pattern
        for index_pattern in existing_indices:
            try:
                field_mapping = get_field_mapping(index_pattern)
                
                # Build base query with time filter
                query = {
                    "bool": {
                        "must": [],
                        "filter": [
                            {
                                "range": {
                                    field_mapping["timestamp_field"]: {
                                        "gte": f"now-{request.dayRange}d",
                                        "lte": "now"
                                    }
                                }
                            }
                        ]
                    }
                }
                
                # Add tactic filter if specified
                if request.tactic and request.tactic != "all":
                    if "tactic_id_field" in field_mapping:
                        query["bool"]["filter"].append({
                            "term": {field_mapping["tactic_id_field"]: request.tactic}
                        })
                    else:
                        query["bool"]["filter"].append({
                            "wildcard": {field_mapping["tactic_field"]: f"{request.tactic} - *"}
                        })
                
                # Determine aggregation field based on index type
                if "technique_id_field" in field_mapping:
                    # CrowdStrike: has separate technique ID field
                    agg_field = field_mapping["technique_id_field"]
                else:
                    # Palo Alto: combined field
                    agg_field = field_mapping["technique_field"]
                
                # Execute aggregation query
                response = await es.search(
                    index=index_pattern,
                    body={
                        "query": query,
                        "size": 0,
                        "aggs": {
                            "top_techniques": {
                                "terms": {
                                    "field": agg_field,
                                    "size": request.limit * 3,  # Get more than needed to handle parsing
                                    "order": {"_count": "desc"}
                                }
                            }
                        }
                    }
                )
                
                # Process aggregation results
                buckets = response.get("aggregations", {}).get("top_techniques", {}).get("buckets", [])
                
                for bucket in buckets:
                    technique_value = bucket["key"]
                    count = bucket["doc_count"]
                    total_detections += count
                    
                    # Parse technique ID from the value
                    if " - " in technique_value:
                        # Palo Alto format: "T1059 - Command and Scripting Interpreter"
                        technique_id = technique_value.split(" - ")[0].strip()
                    else:
                        # CrowdStrike format: just the ID
                        technique_id = technique_value.strip()
                    
                    # Skip if not a valid technique ID
                    if not technique_id.upper().startswith("T"):
                        continue
                    
                    # Aggregate counts across indices
                    if technique_id not in technique_aggregation:
                        technique_aggregation[technique_id] = {
                            "count": 0,
                            "sources": {}
                        }
                    
                    technique_aggregation[technique_id]["count"] += count
                    technique_aggregation[technique_id]["sources"][index_pattern] = count
                
            except ValueError as ve:
                print(f"Skipping unsupported index pattern {index_pattern}: {ve}")
                continue
            except Exception as e:
                print(f"Error processing index {index_pattern}: {e}")
                continue
        
        # Sort techniques by total count and get top N
        sorted_techniques = sorted(
            technique_aggregation.items(),
            key=lambda x: x[1]["count"],
            reverse=True
        )[:request.limit]
        
        # Enrich with technique metadata from MITRE mapping
        results = []
        for technique_id, data in sorted_techniques:
            # Get technique name and tactics from MITRE mapping
            technique_name = get_technique_name(technique_id) or technique_id
            tactic_ids = get_technique_tactics(technique_id)
            tactic_names = [get_tactic_name(tid) or tid for tid in tactic_ids]
            
            results.append({
                "technique_id": technique_id,
                "technique_name": technique_name,
                "count": data["count"],
                "tactic_ids": tactic_ids,
                "tactic_names": tactic_names,
                "sources": data["sources"]
            })
        
        return {
            "techniques": results,
            "total_detections": total_detections,
            "time_range": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "limit": request.limit,
            "tactic_filter": request.tactic
        }
        
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error fetching top techniques: {str(e)}")


    
# Add these models for kill chain mapping

class KillChainRequest(BaseModel):
    """Request for kill chain coverage analysis"""
    indices: List[str]
    dayRange: Optional[int] = 7
    search: Optional[str] = None

class TacticCoverage(BaseModel):
    """Coverage data for a single tactic"""
    tactic_id: str
    tactic_name: str
    techniques_detected: int
    total_detections: int
    top_techniques: List[Dict[str, Any]]
    coverage_percentage: float
    sources: Dict[str, int]

class KillChainResponse(BaseModel):
    """Complete kill chain coverage response"""
    tactics: List[TacticCoverage]
    total_detections: int
    unique_techniques: int
    time_range: Dict[str, str]
    indices_queried: List[str]

# Cyber Kill Chain Phase Definitions (7 phases)
KILL_CHAIN_PHASES = {
    "reconnaissance": {
        "name": "Reconnaissance",
        "name_th": "การสอดแนม",
        "description": "Research, identification and selection of targets"
    },
    "weaponization": {
        "name": "Weaponization", 
        "name_th": "การสร้างอาวุธ",
        "description": "Pairing remote access malware with exploit into a deliverable payload"
    },
    "delivery": {
        "name": "Delivery",
        "name_th": "การส่งมอบ",
        "description": "Transmission of weapon to target environment"
    },
    "exploitation": {
        "name": "Exploitation",
        "name_th": "การโจมตี",
        "description": "Trigger intruders' code to exploit vulnerability"
    },
    "installation": {
        "name": "Installation",
        "name_th": "การติดตั้ง",
        "description": "Installation of malware on the asset"
    },
    "command_control": {
        "name": "Command & Control",
        "name_th": "การสั่งการและควบคุม",
        "description": "Command channel for remote manipulation"
    },
    "actions_objectives": {
        "name": "Actions on Objectives",
        "name_th": "การดำเนินการตามเป้าหมาย",
        "description": "Intruders accomplish their original goals"
    }
}

# Mapping MITRE ATT&CK Tactics to Cyber Kill Chain Phases
MITRE_TO_KILLCHAIN = {
    # Reconnaissance phase
    "TA0043": "reconnaissance",  # Reconnaissance
    
    # Weaponization phase (resource development)
    "TA0042": "weaponization",  # Resource Development
    
    # Delivery phase
    "TA0001": "delivery",  # Initial Access
    
    # Exploitation phase
    "TA0002": "exploitation",  # Execution
    "TA0004": "exploitation",  # Privilege Escalation
    "TA0005": "exploitation",  # Defense Evasion
    
    # Installation phase
    "TA0003": "installation",  # Persistence
    
    # Command & Control phase
    "TA0011": "command_control",  # Command and Control
    
    # Actions on Objectives phase
    "TA0006": "actions_objectives",  # Credential Access
    "TA0007": "actions_objectives",  # Discovery
    "TA0008": "actions_objectives",  # Lateral Movement
    "TA0009": "actions_objectives",  # Collection
    "TA0010": "actions_objectives",  # Exfiltration
    "TA0040": "actions_objectives",  # Impact
}

# Add the kill chain mapping endpoint

@app.post("/api/unified/kill-chain", summary="Get complete kill chain coverage across all tactics")
async def get_kill_chain_coverage(request: KillChainRequest):
    """
    Comprehensive endpoint that maps all detections to the complete MITRE ATT&CK kill chain.
    Returns coverage data for every tactic with technique-level details.
    
    Example request:
    {
        "indices": ["palo-xsiam-*", "crowdstrike-*"],
        "dayRange": 7,
        "search": null
    }
    
    Returns complete kill chain with:
    - Coverage for all 14 MITRE tactics (TA0001-TA0043)
    - Techniques detected per tactic
    - Total detections per tactic
    - Top techniques for each tactic
    - Source breakdown (which index contributed what)
    - Coverage percentage based on available techniques
    """
    try:
        # Filter out Windows indices
        valid_indices = filter_valid_indices(request.indices)
        
        if not valid_indices:
            raise HTTPException(
                status_code=400,
                detail="No valid indices provided. Windows/winlog indices are not supported."
            )
        
        # Validate indices exist
        indices_status = await validate_indices(valid_indices)
        existing_indices = [idx for idx, exists in indices_status.items() if exists]
        
        if not existing_indices:
            raise HTTPException(
                status_code=404,
                detail=f"None of the provided indices exist: {valid_indices}"
            )
        
        # Calculate time range
        from datetime import datetime, timedelta
        end_date = datetime.now()
        start_date = end_date - timedelta(days=request.dayRange)
        
        # Initialize kill chain structure with all tactics
        kill_chain = {}
        for tactic_id, tactic_name in TACTIC_MAP.items():
            kill_chain[tactic_id] = {
                "tactic_id": tactic_id,
                "tactic_name": tactic_name,
                "techniques": {},  # technique_id -> {count, sources, name}
                "total_detections": 0,
                "sources": {}
            }
        
        total_detections = 0
        all_detected_techniques = set()
        
        # Query each index pattern
        for index_pattern in existing_indices:
            try:
                field_mapping = get_field_mapping(index_pattern)
                
                # Build base query
                query = {
                    "bool": {
                        "must": [],
                        "filter": [
                            {
                                "range": {
                                    field_mapping["timestamp_field"]: {
                                        "gte": f"now-{request.dayRange}d",
                                        "lte": "now"
                                    }
                                }
                            }
                        ]
                    }
                }
                
                # Add search filter if provided
                if request.search:
                    search_fields = ["message", "host.name", "user.name"]
                    if "category_field" in field_mapping:
                        search_fields.append(field_mapping["category_field"])
                    
                    query["bool"]["must"].append({
                        "multi_match": {
                            "query": request.search,
                            "fields": search_fields,
                            "fuzziness": "AUTO"
                        }
                    })
                
                # Determine aggregation fields
                if "technique_id_field" in field_mapping:
                    # CrowdStrike: has separate fields
                    technique_agg_field = field_mapping["technique_id_field"]
                    tactic_agg_field = field_mapping["tactic_id_field"]
                else:
                    # Palo Alto: combined fields
                    technique_agg_field = field_mapping["technique_field"]
                    tactic_agg_field = field_mapping["tactic_field"]
                
                # Execute query with nested aggregations
                # First aggregate by tactic, then by technique within each tactic
                response = await es.search(
                    index=index_pattern,
                    body={
                        "query": query,
                        "size": 0,
                        "aggs": {
                            "tactics": {
                                "terms": {
                                    "field": tactic_agg_field,
                                    "size": 50
                                },
                                "aggs": {
                                    "techniques": {
                                        "terms": {
                                            "field": technique_agg_field,
                                            "size": 100
                                        }
                                    }
                                }
                            }
                        }
                    }
                )
                
                # Process aggregation results
                tactic_buckets = response.get("aggregations", {}).get("tactics", {}).get("buckets", [])
                
                for tactic_bucket in tactic_buckets:
                    tactic_value = tactic_bucket["key"]
                    
                    # Parse tactic ID
                    if " - " in tactic_value:
                        # Palo Alto format: "TA0002 - Execution"
                        tactic_id = tactic_value.split(" - ")[0].strip()
                    else:
                        # CrowdStrike format: need to map name to ID
                        # Try to find matching tactic ID
                        tactic_id = None
                        for tid, tname in TACTIC_MAP.items():
                            if tname.lower() == tactic_value.lower():
                                tactic_id = tid
                                break
                        if not tactic_id:
                            continue
                    
                    # Ensure tactic exists in our structure
                    if tactic_id not in kill_chain:
                        kill_chain[tactic_id] = {
                            "tactic_id": tactic_id,
                            "tactic_name": TACTIC_MAP.get(tactic_id, tactic_id),
                            "techniques": {},
                            "total_detections": 0,
                            "sources": {}
                        }
                    
                    # Process techniques within this tactic
                    technique_buckets = tactic_bucket.get("techniques", {}).get("buckets", [])
                    
                    for technique_bucket in technique_buckets:
                        technique_value = technique_bucket["key"]
                        count = technique_bucket["doc_count"]
                        
                        # Parse technique ID
                        if " - " in technique_value:
                            technique_id = technique_value.split(" - ")[0].strip()
                        else:
                            technique_id = technique_value.strip()
                        
                        # Skip if not a valid technique ID
                        if not technique_id.upper().startswith("T"):
                            continue
                        
                        all_detected_techniques.add(technique_id)
                        total_detections += count
                        
                        # Add to kill chain structure
                        if technique_id not in kill_chain[tactic_id]["techniques"]:
                            kill_chain[tactic_id]["techniques"][technique_id] = {
                                "technique_id": technique_id,
                                "technique_name": get_technique_name(technique_id) or technique_id,
                                "count": 0,
                                "sources": {}
                            }
                        
                        kill_chain[tactic_id]["techniques"][technique_id]["count"] += count
                        kill_chain[tactic_id]["techniques"][technique_id]["sources"][index_pattern] = \
                            kill_chain[tactic_id]["techniques"][technique_id]["sources"].get(index_pattern, 0) + count
                        
                        kill_chain[tactic_id]["total_detections"] += count
                        kill_chain[tactic_id]["sources"][index_pattern] = \
                            kill_chain[tactic_id]["sources"].get(index_pattern, 0) + count
                
            except ValueError as ve:
                print(f"Skipping unsupported index pattern {index_pattern}: {ve}")
                continue
            except Exception as e:
                print(f"Error processing index {index_pattern}: {e}")
                import traceback
                traceback.print_exc()
                continue
        
        # Format results for each tactic
        tactics_coverage = []
        
        # Get all tactics in order (TA0043, TA0042, TA0001-TA0011, TA0040)
        tactic_order = ["TA0043", "TA0042"] + [f"TA{str(i).zfill(4)}" for i in range(1, 12)] + ["TA0040"]
        
        for tactic_id in tactic_order:
            if tactic_id not in TACTIC_MAP:
                continue
                
            tactic_data = kill_chain.get(tactic_id, {
                "tactic_id": tactic_id,
                "tactic_name": TACTIC_MAP[tactic_id],
                "techniques": {},
                "total_detections": 0,
                "sources": {}
            })
            
            # Get top 5 techniques for this tactic
            sorted_techniques = sorted(
                tactic_data["techniques"].values(),
                key=lambda x: x["count"],
                reverse=True
            )[:5]
            
            # Calculate coverage percentage
            # Count total available techniques for this tactic in MITRE mapping
            available_techniques = sum(
                1 for tech_data in TECHNIQUE_MAP.values()
                if tactic_id in tech_data.get("tactics", [])
            )
            
            coverage_percentage = 0.0
            if available_techniques > 0:
                detected_count = len(tactic_data["techniques"])
                coverage_percentage = (detected_count / available_techniques) * 100
            
            tactics_coverage.append({
                "tactic_id": tactic_id,
                "tactic_name": tactic_data["tactic_name"],
                "techniques_detected": len(tactic_data["techniques"]),
                "total_detections": tactic_data["total_detections"],
                "top_techniques": sorted_techniques,
                "coverage_percentage": round(coverage_percentage, 2),
                "sources": tactic_data["sources"],
                "available_techniques": available_techniques
            })
        
        return {
            "tactics": tactics_coverage,
            "total_detections": total_detections,
            "unique_techniques": len(all_detected_techniques),
            "time_range": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "indices_queried": existing_indices,
            "total_tactics": len([t for t in tactics_coverage if t["total_detections"] > 0])
        }
        
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error mapping kill chain: {str(e)}")

@app.post("/api/unified/cyber-kill-chain", summary="Get Cyber Kill Chain coverage (7 phases)")
async def get_cyber_kill_chain_coverage(request: KillChainRequest):
    """
    Comprehensive endpoint that maps all detections to the Cyber Kill Chain methodology (7 phases).
    Converts MITRE ATT&CK tactics to their corresponding kill chain phases.
    
    Example request:
    {
        "indices": ["palo-xsiam-*", "crowdstrike-*"],
        "dayRange": 7,
        "search": null
    }
    
    Returns Cyber Kill Chain with 7 phases:
    1. Reconnaissance (การสอดแนม)
    2. Weaponization (การสร้างอาวุธ)
    3. Delivery (การส่งมอบ)
    4. Exploitation (การโจมตี)
    5. Installation (การติดตั้ง)
    6. Command & Control (การสั่งการและควบคุม)
    7. Actions on Objectives (การดำเนินการตามเป้าหมาย)
    
    Each phase includes:
    - Techniques detected in this phase
    - Total detections per phase
    - Top techniques for each phase
    - Source breakdown (which index contributed what)
    - Coverage percentage based on MITRE techniques in that phase
    """
    try:
        # Filter out Windows indices
        valid_indices = filter_valid_indices(request.indices)
        
        if not valid_indices:
            raise HTTPException(
                status_code=400,
                detail="No valid indices provided. Windows/winlog indices are not supported."
            )
        
        # Validate indices exist
        indices_status = await validate_indices(valid_indices)
        existing_indices = [idx for idx, exists in indices_status.items() if exists]
        
        if not existing_indices:
            raise HTTPException(
                status_code=404,
                detail=f"None of the provided indices exist: {valid_indices}"
            )
        
        # Calculate time range
        from datetime import datetime, timedelta
        end_date = datetime.now()
        start_date = end_date - timedelta(days=request.dayRange)
        
        # Initialize kill chain structure with all 7 phases
        kill_chain = {}
        for phase_id, phase_data in KILL_CHAIN_PHASES.items():
            kill_chain[phase_id] = {
                "phase_id": phase_id,
                "phase_name": phase_data["name"],
                "phase_name_th": phase_data["name_th"],
                "techniques": {},  # technique_id -> {count, sources, name, tactic}
                "total_detections": 0,
                "sources": {},
                "tactics": set()  # Track which MITRE tactics contributed
            }
        
        total_detections = 0
        all_detected_techniques = set()
        
        # Query each index pattern
        for index_pattern in existing_indices:
            try:
                field_mapping = get_field_mapping(index_pattern)
                
                # Build base query
                query = {
                    "bool": {
                        "must": [],
                        "filter": [
                            {
                                "range": {
                                    field_mapping["timestamp_field"]: {
                                        "gte": f"now-{request.dayRange}d",
                                        "lte": "now"
                                    }
                                }
                            }
                        ]
                    }
                }
                
                # Add search filter if provided
                if request.search:
                    search_fields = ["message", "host.name", "user.name"]
                    if "category_field" in field_mapping:
                        search_fields.append(field_mapping["category_field"])
                    
                    query["bool"]["must"].append({
                        "multi_match": {
                            "query": request.search,
                            "fields": search_fields,
                            "fuzziness": "AUTO"
                        }
                    })
                
                # Determine aggregation fields
                if "technique_id_field" in field_mapping:
                    technique_agg_field = field_mapping["technique_id_field"]
                    tactic_agg_field = field_mapping["tactic_id_field"]
                else:
                    technique_agg_field = field_mapping["technique_field"]
                    tactic_agg_field = field_mapping["tactic_field"]
                
                # Execute query with nested aggregations
                response = await es.search(
                    index=index_pattern,
                    body={
                        "query": query,
                        "size": 0,
                        "aggs": {
                            "tactics": {
                                "terms": {
                                    "field": tactic_agg_field,
                                    "size": 50
                                },
                                "aggs": {
                                    "techniques": {
                                        "terms": {
                                            "field": technique_agg_field,
                                            "size": 100
                                        }
                                    }
                                }
                            }
                        }
                    }
                )
                
                # Process aggregation results
                tactic_buckets = response.get("aggregations", {}).get("tactics", {}).get("buckets", [])
                
                for tactic_bucket in tactic_buckets:
                    tactic_value = tactic_bucket["key"]
                    
                    # Parse tactic ID from different formats
                    if " - " in tactic_value:
                        # Palo Alto format: "TA0002 - Execution"
                        tactic_id = tactic_value.split(" - ")[0].strip()
                    else:
                        # CrowdStrike format: map name to ID
                        tactic_id = None
                        for tid, tname in TACTIC_MAP.items():
                            if tname.lower() == tactic_value.lower():
                                tactic_id = tid
                                break
                        if not tactic_id:
                            continue
                    
                    # Map MITRE tactic to Cyber Kill Chain phase
                    phase_id = MITRE_TO_KILLCHAIN.get(tactic_id)
                    if not phase_id:
                        continue
                    
                    kill_chain[phase_id]["tactics"].add(tactic_id)
                    
                    # Process techniques within this tactic
                    technique_buckets = tactic_bucket.get("techniques", {}).get("buckets", [])
                    
                    for technique_bucket in technique_buckets:
                        technique_value = technique_bucket["key"]
                        count = technique_bucket["doc_count"]
                        
                        # Parse technique ID
                        if " - " in technique_value:
                            technique_id = technique_value.split(" - ")[0].strip()
                        else:
                            technique_id = technique_value.strip()
                        
                        # Skip if not a valid technique ID
                        if not technique_id.upper().startswith("T"):
                            continue
                        
                        all_detected_techniques.add(technique_id)
                        total_detections += count
                        
                        # Add to kill chain structure
                        if technique_id not in kill_chain[phase_id]["techniques"]:
                            kill_chain[phase_id]["techniques"][technique_id] = {
                                "technique_id": technique_id,
                                "technique_name": get_technique_name(technique_id) or technique_id,
                                "count": 0,
                                "sources": {},
                                "tactic_id": tactic_id,
                                "tactic_name": TACTIC_MAP.get(tactic_id, tactic_id)
                            }
                        
                        kill_chain[phase_id]["techniques"][technique_id]["count"] += count
                        kill_chain[phase_id]["techniques"][technique_id]["sources"][index_pattern] = \
                            kill_chain[phase_id]["techniques"][technique_id]["sources"].get(index_pattern, 0) + count
                        
                        kill_chain[phase_id]["total_detections"] += count
                        kill_chain[phase_id]["sources"][index_pattern] = \
                            kill_chain[phase_id]["sources"].get(index_pattern, 0) + count
                
            except ValueError as ve:
                print(f"Skipping unsupported index pattern {index_pattern}: {ve}")
                continue
            except Exception as e:
                print(f"Error processing index {index_pattern}: {e}")
                import traceback
                traceback.print_exc()
                continue
        
        # Format results for each phase (in kill chain order)
        phases_coverage = []
        phase_order = [
            "reconnaissance",
            "weaponization", 
            "delivery",
            "exploitation",
            "installation",
            "command_control",
            "actions_objectives"
        ]
        
        for phase_id in phase_order:
            phase_data = kill_chain[phase_id]
            
            # Get top 5 techniques for this phase
            sorted_techniques = sorted(
                phase_data["techniques"].values(),
                key=lambda x: x["count"],
                reverse=True
            )[:5]
            
            # Calculate coverage percentage
            # Count total available techniques that map to this phase
            available_techniques = 0
            for tech_id, tech_data in TECHNIQUE_MAP.items():
                # Check if any of this technique's tactics map to this phase
                for tactic_id in tech_data.get("tactics", []):
                    if MITRE_TO_KILLCHAIN.get(tactic_id) == phase_id:
                        available_techniques += 1
                        break
            
            coverage_percentage = 0.0
            if available_techniques > 0:
                detected_count = len(phase_data["techniques"])
                coverage_percentage = (detected_count / available_techniques) * 100
            
            phases_coverage.append({
                "phase_id": phase_id,
                "phase_name": phase_data["phase_name"],
                "phase_name_th": phase_data["phase_name_th"],
                "techniques_detected": len(phase_data["techniques"]),
                "total_detections": phase_data["total_detections"],
                "top_techniques": sorted_techniques,
                "coverage_percentage": round(coverage_percentage, 2),
                "sources": phase_data["sources"],
                "available_techniques": available_techniques,
                "mitre_tactics": list(phase_data["tactics"])
            })
        
        return {
            "phases": phases_coverage,
            "total_detections": total_detections,
            "unique_techniques": len(all_detected_techniques),
            "time_range": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "indices_queried": existing_indices,
            "active_phases": len([p for p in phases_coverage if p["total_detections"] > 0]),
            "methodology": "Cyber Kill Chain (Lockheed Martin)"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error mapping Cyber Kill Chain: {str(e)}")


@app.get("/", summary="Health Check")
async def root():
    """Check if API is running"""
    return {
        "status": "ok",
        "message": "MITRE ATT&CK Multi-Index API",
        "endpoints": {
            "legacy": ["/api/technique-stats-date", "/api/stats-date"],
            "multi-index": [
                "/api/multi-index/technique-stats",
                "/api/multi-index/stats",
                "/api/multi-index/search"
            ],
            "unified": [
                "/api/unified/technique-stats",
                "/api/unified/stats",
                "/api/unified/search",
                "/api/unified/top-techniques",
                "/api/unified/kill-chain"
            ]
        }
    }
    
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "multi_pattern:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
