# ml/train/prepare_dataset.py

"""Prepare training dataset from Elasticsearch"""

import re
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from elasticsearch import Elasticsearch
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
import json
from config import *
from utils.feature_engineering import extract_features, CyberKillChainFeatureExtractor


class DatasetPreparer:
    """Prepare and label dataset for training"""
    
    def __init__(self, es_host: str = ES_HOST):
        self.es = Elasticsearch(
            es_host,
            basic_auth=(ES_USERNAME, ES_PASSWORD) if ES_USERNAME else None
        )
        
    def fetch_logs_from_es(
        self, 
        index_pattern: str = ES_INDEX_PATTERN, 
        size: int = 10000,
        days_back: int = 30
    ) -> List[Dict]:
        """Fetch logs from Elasticsearch"""
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=days_back)
        
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
            print(f"Fetching logs from {index_pattern}...")
            res = self.es.search(index=index_pattern, body=query)
            logs = [hit["_source"] for hit in res["hits"]["hits"]]
            print(f"✓ Fetched {len(logs)} logs")
            return logs
        except Exception as e:
            print(f"✗ Error fetching from Elasticsearch: {e}")
            return []
    
    def load_labeled_data(self, file_path: str) -> List[Dict]:
        """Load labeled data from JSON file"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            print(f"✓ Loaded {len(data)} labeled samples from {file_path}")
            return data
        except FileNotFoundError:
            print(f"✗ File not found: {file_path}")
            return []
    
    def apply_heuristic_labels(self, logs: List[Dict]) -> List[Dict]:
        """
        Apply improved heuristic labeling rules
        NOTE: Replace this with real labeled data for production!
        """
        print("Applying heuristic labels (TEMPORARY - use real labels in production)...")
        
        for log in logs:
            msg = log.get("message", "").lower()
            event_type = log.get("event_type", "").lower()
            
            # Initialize phase
            phase = "actions_objectives"  # Default
            confidence = 0.0
            
            # Reconnaissance indicators
            recon_score = sum([
                3 if any(kw in msg for kw in ["scan", "probe", "nmap", "reconnaissance"]) else 0,
                2 if "port" in msg and any(kw in msg for kw in ["open", "closed", "filtered"]) else 0,
                2 if any(kw in msg for kw in ["dns query", "whois", "dig"]) else 0,
                1 if re.search(r"enum", msg) else 0
            ])
            
            # Weaponization indicators
            weapon_score = sum([
                3 if any(kw in msg for kw in ["payload", "exploit kit", "malware", "weaponization"]) else 0,
                2 if any(kw in msg for kw in ["msfvenom", "metasploit", "cobalt strike"]) else 0,
                2 if "dropper" in msg else 0
            ])
            
            # Delivery indicators
            delivery_score = sum([
                3 if any(kw in msg for kw in ["phishing", "email", "attachment", "delivery"]) else 0,
                2 if any(kw in msg for kw in ["spearphishing", "watering hole"]) else 0,
                2 if "download" in msg and any(ext in msg for ext in [".exe", ".zip", ".pdf"]) else 0
            ])
            
            # Exploitation indicators
            exploit_score = sum([
                3 if any(kw in msg for kw in ["exploit", "vulnerability", "cve-"]) else 0,
                3 if any(kw in msg for kw in ["buffer overflow", "sql injection", "rce"]) else 0,
                2 if "shellcode" in msg else 0,
                2 if any(kw in msg for kw in ["privilege escalation", "elevation"]) else 0
            ])
            
            # Installation indicators
            install_score = sum([
                3 if any(kw in msg for kw in ["install", "persistence", "registry"]) else 0,
                2 if any(kw in msg for kw in ["scheduled task", "startup", "autorun"]) else 0,
                2 if any(kw in msg for kw in ["service creation", "dll injection"]) else 0
            ])
            
            # C2 indicators
            c2_score = sum([
                3 if any(kw in msg for kw in ["c2", "command and control", "beacon"]) else 0,
                2 if any(kw in msg for kw in ["callback", "heartbeat", "check-in"]) else 0,
                2 if "proxy" in msg or "tunnel" in msg else 0,
                1 if any(port in msg for port in ["4444", "8080", "443"]) else 0
            ])
            
            # Actions on Objectives indicators
            actions_score = sum([
                3 if any(kw in msg for kw in ["exfiltration", "data theft", "ransomware"]) else 0,
                2 if any(kw in msg for kw in ["encryption", "deletion", "destruction"]) else 0,
                2 if any(kw in msg for kw in ["lateral movement", "pivoting"]) else 0
            ])
            
            # Determine phase based on highest score
            scores = {
                "reconnaissance": recon_score,
                "weaponization": weapon_score,
                "delivery": delivery_score,
                "exploitation": exploit_score,
                "installation": install_score,
                "command_control": c2_score,
                "actions_objectives": actions_score
            }
            
            max_score = max(scores.values())
            if max_score > 0:
                phase = max(scores, key=scores.get)
                confidence = min(max_score / 10.0, 1.0)  # Normalize to 0-1
            
            log["phase"] = phase
            log["label_confidence"] = confidence
        
        return logs
    
    def balance_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """Balance dataset using stratified sampling"""
        from sklearn.utils import resample
        
        # Get class distribution
        class_counts = df["label"].value_counts()
        print("\nOriginal class distribution:")
        for phase_idx, count in class_counts.items():
            print(f"  {PHASES[phase_idx]}: {count}")
        
        # Find minority and majority class sizes
        min_samples = class_counts.min()
        max_samples = class_counts.max()
        target_samples = int((min_samples + max_samples) / 2)  # Target middle ground
        
        # Resample each class
        balanced_dfs = []
        for phase_idx in range(len(PHASES)):
            class_df = df[df["label"] == phase_idx]
            
            if len(class_df) == 0:
                continue
            
            if len(class_df) < target_samples:
                # Oversample minority class
                class_df = resample(
                    class_df,
                    n_samples=target_samples,
                    random_state=RANDOM_STATE,
                    replace=True
                )
            elif len(class_df) > target_samples:
                # Undersample majority class
                class_df = resample(
                    class_df,
                    n_samples=target_samples,
                    random_state=RANDOM_STATE,
                    replace=False
                )
            
            balanced_dfs.append(class_df)
        
        balanced_df = pd.concat(balanced_dfs, ignore_index=True)
        balanced_df = balanced_df.sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)
        
        print("\nBalanced class distribution:")
        balanced_counts = balanced_df["label"].value_counts()
        for phase_idx, count in balanced_counts.items():
            print(f"  {PHASES[phase_idx]}: {count}")
        
        return balanced_df
    
    def build_dataset(
        self, 
        use_elasticsearch: bool = True,
        labeled_file: str = None,
        balance: bool = True
    ) -> Tuple[pd.DataFrame, CyberKillChainFeatureExtractor]:
        """
        Build complete training dataset
        
        Returns:
            Tuple of (features_df, feature_extractor)
        """
        logs = []
        
        # Load from labeled file if provided
        if labeled_file and Path(labeled_file).exists():
            logs = self.load_labeled_data(labeled_file)
        
        # Fetch from Elasticsearch
        if use_elasticsearch:
            es_logs = self.fetch_logs_from_es()
            es_logs = self.apply_heuristic_labels(es_logs)
            logs.extend(es_logs)
        
        if not logs:
            raise ValueError("No data available for training!")
        
        print(f"\nTotal logs collected: {len(logs)}")
        
        # Extract features
        print("\nExtracting features...")
        extractor = CyberKillChainFeatureExtractor(max_tfidf_features=MAX_TFIDF_FEATURES)
        df, extractor = extract_features(logs, extractor=extractor, fit=True)
        
        # Add labels
        df["label"] = [PHASES.index(log["phase"]) for log in logs]
        
        # Balance dataset
        if balance:
            df = self.balance_dataset(df)
        
        # Remove non-feature columns
        columns_to_drop = ["message", "timestamp", "phase", "label_confidence"]
        df = df.drop(columns=[col for col in columns_to_drop if col in df.columns])
        
        print(f"\n✓ Dataset prepared: {len(df)} samples, {len(df.columns)-1} features")
        
        return df, extractor


def main():
    """Main execution"""
    preparer = DatasetPreparer()
    
    # Build dataset
    df, extractor = preparer.build_dataset(
        use_elasticsearch=True,
        labeled_file=None,  # Provide path to labeled data if available
        balance=True
    )
    
    # Save dataset
    output_file = DATA_DIR / f"training_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pkl"
    df.to_pickle(output_file)
    print(f"\n✓ Dataset saved to {output_file}")
    
    # Save feature extractor
    extractor_file = DATA_DIR / "feature_extractor.pkl"
    import joblib
    joblib.dump(extractor, extractor_file)
    print(f"✓ Feature extractor saved to {extractor_file}")
    
    return df, extractor


if __name__ == "__main__":
    df, extractor = main()