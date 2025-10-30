# feature_engineering.py
"""Feature engineering for cyber kill chain detection"""

import pandas as pd
import numpy as np
import re
from datetime import datetime
from typing import List, Dict
from sklearn.feature_extraction.text import TfidfVectorizer
import hashlib


class CyberKillChainFeatureExtractor:
    """Extract features from security logs for kill chain classification"""
    
    def __init__(self, max_tfidf_features: int = 100):
        self.max_tfidf_features = max_tfidf_features
        self.tfidf_vectorizer = None
        self.event_type_columns = []
        self.fitted = False
        
    def extract_basic_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract basic statistical features"""
        # Ensure required columns exist
        for col in ["event_type", "message", "timestamp"]:
            if col not in df.columns:
                df[col] = ""
        
        # Message length features
        df["msg_length"] = df["message"].astype(str).apply(len)
        df["msg_word_count"] = df["message"].astype(str).apply(lambda x: len(x.split()))
        df["msg_char_entropy"] = df["message"].astype(str).apply(self._calculate_entropy)
        
        # Pattern detection
        df["has_ip"] = df["message"].astype(str).apply(
            lambda x: 1 if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", x) else 0
        )
        df["has_url"] = df["message"].astype(str).apply(
            lambda x: 1 if re.search(r"https?://", x, re.IGNORECASE) else 0
        )
        df["has_email"] = df["message"].astype(str).apply(
            lambda x: 1 if re.search(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", x) else 0
        )
        df["has_exec"] = df["message"].astype(str).apply(
            lambda x: 1 if any(ext in x.lower() for ext in [".exe", ".bat", ".sh", ".ps1", ".dll"]) else 0
        )
        df["has_powershell"] = df["message"].astype(str).apply(
            lambda x: 1 if "powershell" in x.lower() else 0
        )
        df["has_cmd"] = df["message"].astype(str).apply(
            lambda x: 1 if any(cmd in x.lower() for cmd in ["cmd.exe", "cmd /c"]) else 0
        )
        
        # Port detection
        df["has_high_port"] = df["message"].astype(str).apply(
            lambda x: 1 if re.search(r"port[:\s]+([0-9]{4,5})", x, re.IGNORECASE) else 0
        )
        df["has_common_port"] = df["message"].astype(str).apply(
            lambda x: 1 if re.search(r"port[:\s]+(80|443|22|21|3389|445)", x, re.IGNORECASE) else 0
        )
        
        # Security keywords
        df["has_scan"] = df["message"].astype(str).apply(
            lambda x: 1 if any(kw in x.lower() for kw in ["scan", "probe", "reconnaissance"]) else 0
        )
        df["has_exploit"] = df["message"].astype(str).apply(
            lambda x: 1 if any(kw in x.lower() for kw in ["exploit", "vulnerability", "cve-"]) else 0
        )
        df["has_payload"] = df["message"].astype(str).apply(
            lambda x: 1 if any(kw in x.lower() for kw in ["payload", "shellcode", "injection"]) else 0
        )
        df["has_c2"] = df["message"].astype(str).apply(
            lambda x: 1 if any(kw in x.lower() for kw in ["c2", "command and control", "beacon", "callback"]) else 0
        )
        df["has_exfiltration"] = df["message"].astype(str).apply(
            lambda x: 1 if any(kw in x.lower() for kw in ["exfil", "download", "upload", "transfer"]) else 0
        )
        
        # Authentication/Authorization
        df["has_failed_login"] = df["message"].astype(str).apply(
            lambda x: 1 if any(kw in x.lower() for kw in ["failed login", "authentication failed", "access denied"]) else 0
        )
        df["has_privilege_escalation"] = df["message"].astype(str).apply(
            lambda x: 1 if any(kw in x.lower() for kw in ["sudo", "admin", "root", "privilege", "elevation"]) else 0
        )
        
        # Network traffic indicators
        df["has_suspicious_traffic"] = df["message"].astype(str).apply(
            lambda x: 1 if any(kw in x.lower() for kw in ["anomaly", "unusual", "suspicious", "malicious"]) else 0
        )
        
        # Event type features
        df["event_type_len"] = df["event_type"].astype(str).apply(len)
        
        return df
    
    def extract_temporal_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract time-based features"""
        if "timestamp" not in df.columns or df["timestamp"].isna().all():
            df["hour"] = 0
            df["day_of_week"] = 0
            df["is_weekend"] = 0
            df["is_night"] = 0
            df["time_delta"] = 0
            return df
        
        try:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
            df = df.sort_values("timestamp")
            
            df["hour"] = df["timestamp"].dt.hour
            df["day_of_week"] = df["timestamp"].dt.dayofweek
            df["is_weekend"] = (df["day_of_week"] >= 5).astype(int)
            df["is_night"] = ((df["hour"] >= 22) | (df["hour"] <= 6)).astype(int)
            
            # Time between events
            df["time_delta"] = df["timestamp"].diff().dt.total_seconds().fillna(0)
            df["time_delta"] = df["time_delta"].clip(upper=3600)  # Cap at 1 hour
            
        except Exception as e:
            print(f"Warning: Could not extract temporal features: {e}")
            df["hour"] = 0
            df["day_of_week"] = 0
            df["is_weekend"] = 0
            df["is_night"] = 0
            df["time_delta"] = 0
        
        return df
    
    def extract_text_features(self, df: pd.DataFrame, fit: bool = False) -> pd.DataFrame:
        """Extract TF-IDF features from message text"""
        messages = df["message"].fillna("").astype(str)
        
        if fit or self.tfidf_vectorizer is None:
            self.tfidf_vectorizer = TfidfVectorizer(
                max_features=self.max_tfidf_features,
                stop_words="english",
                ngram_range=(1, 2),
                min_df=2,
                max_df=0.8
            )
            tfidf_matrix = self.tfidf_vectorizer.fit_transform(messages)
        else:
            tfidf_matrix = self.tfidf_vectorizer.transform(messages)
        
        # Convert to DataFrame
        tfidf_df = pd.DataFrame(
            tfidf_matrix.toarray(),
            columns=[f"tfidf_{i}" for i in range(tfidf_matrix.shape[1])],
            index=df.index
        )
        
        return pd.concat([df.reset_index(drop=True), tfidf_df.reset_index(drop=True)], axis=1)
    
    def encode_categorical(self, df: pd.DataFrame, fit: bool = False) -> pd.DataFrame:
        """One-hot encode categorical variables"""
        if fit:
            # Store event types seen during training
            self.event_type_columns = df["event_type"].unique().tolist()
        
        # One-hot encode
        df_encoded = pd.get_dummies(df, columns=["event_type"], prefix="event", dummy_na=True)
        
        # Ensure all expected columns exist (important for prediction)
        if not fit and self.event_type_columns:
            for col in self.event_type_columns:
                col_name = f"event_{col}"
                if col_name not in df_encoded.columns:
                    df_encoded[col_name] = 0
        
        return df_encoded
    
    def extract_all_features(self, df: pd.DataFrame, fit: bool = False) -> pd.DataFrame:
        """Extract all features"""
        df = df.copy()
        
        # Basic features
        df = self.extract_basic_features(df)
        
        # Temporal features
        df = self.extract_temporal_features(df)
        
        # Text features
        df = self.extract_text_features(df, fit=fit)
        
        # Categorical encoding
        df = self.encode_categorical(df, fit=fit)
        
        if fit:
            self.fitted = True
        
        return df
    
    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        text = text.lower()
        entropy = 0.0
        for char in set(text):
            p = text.count(char) / len(text)
            if p > 0:
                entropy -= p * np.log2(p)
        return entropy


def extract_features(logs: List[Dict], extractor: CyberKillChainFeatureExtractor = None, fit: bool = False) -> pd.DataFrame:
    """
    Main function to extract features from logs
    
    Args:
        logs: List of log dictionaries
        extractor: Feature extractor instance (will create new if None)
        fit: Whether to fit the extractor (for training)
    
    Returns:
        DataFrame with extracted features
    """
    if extractor is None:
        extractor = CyberKillChainFeatureExtractor()
    
    df = pd.DataFrame(logs)
    df = extractor.extract_all_features(df, fit=fit)
    
    return df, extractor