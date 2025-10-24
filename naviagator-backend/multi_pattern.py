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
MAPPING_PATH = Path(__file__).parent / "../public/data/enterprise-attack.json"
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
    
@app.get("/", summary="Health Check")
async def root():
    """Check if API is running"""
    return {
        "status": "ok",
        "message": "MITRE ATT&CK Multi-Index API",
        "endpoints": {
            "legacy": ["/api/technique-stats-date", "/api/stats-date"],
            "multi-index": ["/api/multi-index/technique-stats", "/api/multi-index/stats", "/api/multi-index/search"]
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
