"""
ml_api.py - FastAPI service for cyber kill chain ML predictions
"""
import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import pandas as pd
import joblib
from elasticsearch import Elasticsearch
import numpy as np

app = FastAPI(title="Cyber Kill Chain ML API")
ML_API_PORT = int(os.getenv("ML_API_PORT", 8000))

# CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load model at startup
MODEL_PATH = "ml/models/killchain_xgb.pkl"
model_artifact = joblib.load(MODEL_PATH)
ml_model = model_artifact["model"]
phases = model_artifact["phases"]

# Elasticsearch client
es = Elasticsearch("http://localhost:9200")

# Request/Response models
class PredictionRequest(BaseModel):
    indices: List[str]
    day_range: int = 30
    confidence_threshold: float = 0.6

class TechniqueDetection(BaseModel):
    technique_id: str
    technique_name: str
    count: int
    confidence: float
    sources: Dict[str, int]
    tactic_id: Optional[str] = None
    tactic_name: Optional[str] = None

class PhasePrediction(BaseModel):
    phase_id: str
    phase_name: str
    phase_name_th: str
    total_detections: int
    predicted_detections: int  # ML predictions
    rule_based_detections: int  # Legacy rule-based
    techniques_detected: int
    available_techniques: int
    coverage_percentage: float
    confidence_score: float  # Average confidence
    sources: Dict[str, int]
    mitre_tactics: List[str]
    top_techniques: List[TechniqueDetection]

class MLKillChainResponse(BaseModel):
    total_detections: int
    ml_predictions: int
    unique_techniques: int
    active_phases: int
    methodology: str
    model_version: str
    confidence_threshold: float
    time_range: Dict[str, str]
    indices_queried: List[str]
    phases: List[PhasePrediction]


# Feature engineering (matching your training code)
def extract_features(logs: List[dict]) -> pd.DataFrame:
    """Extract features from raw logs - must match training pipeline"""
    import re
    
    df = pd.DataFrame(logs)
    
    # Normalize columns
    for col in ["event_type", "message"]:
        if col not in df.columns:
            df[col] = ""
    
    # Feature extraction
    df["msg_length"] = df["message"].astype(str).apply(len)
    df["has_ip"] = df["message"].astype(str).apply(
        lambda x: 1 if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", x) else 0
    )
    df["has_url"] = df["message"].astype(str).apply(lambda x: 1 if "http" in x else 0)
    df["has_exec"] = df["message"].astype(str).apply(
        lambda x: 1 if any(ext in x for ext in [".exe", ".bat", ".sh"]) else 0
    )
    df["event_type_len"] = df["event_type"].astype(str).apply(len)
    
    # One-hot encode event_type (must match training columns)
    df = pd.get_dummies(df, columns=["event_type"], dummy_na=True)
    
    return df


def fetch_logs_from_es(indices: List[str], day_range: int, size: int = 5000) -> List[dict]:
    """Fetch logs from Elasticsearch"""
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=day_range)
    
    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {
                        "gte": start_time.isoformat(),
                        "lte": end_time.isoformat()
                    }}}
                ]
            }
        },
        "size": size,
        "sort": [{"@timestamp": "desc"}]
    }
    
    try:
        res = es.search(index=",".join(indices), body=query)
        return [hit["_source"] for hit in res["hits"]["hits"]]
    except Exception as e:
        print(f"ES query error: {e}")
        return []


def align_features(df: pd.DataFrame, training_columns: List[str]) -> pd.DataFrame:
    """Ensure prediction features match training features"""
    # Add missing columns
    for col in training_columns:
        if col not in df.columns:
            df[col] = 0
    
    # Remove extra columns and reorder
    df = df[training_columns]
    return df


@app.post("/api/ml/predict-killchain", response_model=MLKillChainResponse)
async def predict_kill_chain(request: PredictionRequest):
    """
    ML-based cyber kill chain prediction endpoint
    """
    try:
        # Fetch logs
        logs = fetch_logs_from_es(request.indices, request.day_range)
        
        if not logs:
            raise HTTPException(status_code=404, detail="No logs found")
        
        # Extract features
        features_df = extract_features(logs)
        
        # Get training columns from model (if saved) or use current columns
        training_columns = features_df.columns.tolist()
        if hasattr(ml_model, 'feature_names_in_'):
            training_columns = ml_model.feature_names_in_.tolist()
        
        # Align features
        X = align_features(features_df, training_columns)
        
        # Predict phases
        predictions = ml_model.predict(X)
        probabilities = ml_model.predict_proba(X)
        
        # Add predictions back to logs
        for i, log in enumerate(logs):
            log['predicted_phase'] = phases[predictions[i]]
            log['prediction_confidence'] = float(probabilities[i].max())
            log['prediction_probs'] = {
                phases[j]: float(probabilities[i][j]) 
                for j in range(len(phases))
            }
        
        # Filter by confidence threshold
        high_confidence_logs = [
            log for log in logs 
            if log['prediction_confidence'] >= request.confidence_threshold
        ]
        
        # Aggregate by phase
        phase_stats = {}
        for phase_name in phases:
            phase_logs = [
                log for log in high_confidence_logs 
                if log['predicted_phase'] == phase_name
            ]
            
            # Calculate sources
            sources = {}
            for log in phase_logs:
                source = log.get('event.dataset', 'unknown')
                sources[source] = sources.get(source, 0) + 1
            
            # Calculate average confidence
            avg_confidence = (
                np.mean([log['prediction_confidence'] for log in phase_logs])
                if phase_logs else 0.0
            )
            
            phase_stats[phase_name] = {
                'logs': phase_logs,
                'count': len(phase_logs),
                'sources': sources,
                'confidence': float(avg_confidence)
            }
        
        # Build response
        phases_response = []
        phase_name_map = {
            'reconnaissance': ('Reconnaissance', 'การสำรวจ'),
            'weaponization': ('Weaponization', 'การสร้างอาวุธ'),
            'delivery': ('Delivery', 'การส่งมอบ'),
            'exploitation': ('Exploitation', 'การโจมตี'),
            'installation': ('Installation', 'การติดตั้ง'),
            'command_control': ('Command & Control', 'การควบคุม'),
            'actions_objectives': ('Actions on Objectives', 'การดำเนินการ')
        }
        
        for phase_id in phases:
            stats = phase_stats[phase_id]
            name_en, name_th = phase_name_map.get(phase_id, (phase_id, phase_id))
            
            phases_response.append(PhasePrediction(
                phase_id=phase_id,
                phase_name=name_en,
                phase_name_th=name_th,
                total_detections=stats['count'],
                predicted_detections=stats['count'],
                rule_based_detections=0,  # Set to 0 for pure ML
                techniques_detected=len(set(log.get('technique_id', '') for log in stats['logs'])),
                available_techniques=10,  # Could be dynamic
                coverage_percentage=min(100.0, stats['count'] / 10.0) if stats['count'] else 0.0,
                confidence_score=stats['confidence'],
                sources=stats['sources'],
                mitre_tactics=[],  # Extract from logs if available
                top_techniques=[]  # Could aggregate techniques
            ))
        
        return MLKillChainResponse(
            total_detections=len(high_confidence_logs),
            ml_predictions=len(high_confidence_logs),
            unique_techniques=len(set(log.get('technique_id', '') for log in high_confidence_logs)),
            active_phases=sum(1 for p in phases_response if p.total_detections > 0),
            methodology="Machine Learning (XGBoost)",
            model_version="v1.0",
            confidence_threshold=request.confidence_threshold,
            time_range={
                "start": (datetime.utcnow() - timedelta(days=request.day_range)).isoformat(),
                "end": datetime.utcnow().isoformat()
            },
            indices_queried=request.indices,
            phases=phases_response
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")


@app.get("/api/ml/model-info")
async def get_model_info():
    """Get model metadata"""
    return {
        "model_type": "XGBoost Classifier",
        "phases": phases,
        "num_classes": len(phases),
        "model_path": MODEL_PATH,
        "features": ml_model.feature_names_in_.tolist() if hasattr(ml_model, 'feature_names_in_') else []
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy", "model_loaded": ml_model is not None}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=ML_API_PORT)