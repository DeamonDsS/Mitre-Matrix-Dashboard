# ============================================================================
# ml/config.py
# ============================================================================
"""Configuration for ML pipeline"""

import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).parent
MODEL_DIR = BASE_DIR / "models"
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"

# Create directories
MODEL_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

# Elasticsearch
ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ES_USERNAME = os.getenv("ES_USERNAME", "elastic")
ES_PASSWORD = os.getenv("ES_PASSWORD", "changeme")
ES_INDEX_PATTERN = "logs-*"

# Cyber Kill Chain Phases
PHASES = [
    "reconnaissance",
    "weaponization", 
    "delivery",
    "exploitation",
    "installation",
    "command_control",
    "actions_objectives"
]

PHASE_NAMES = {
    "reconnaissance": {"en": "Reconnaissance", "th": "การสำรวจ"},
    "weaponization": {"en": "Weaponization", "th": "การสร้างอาวุธ"},
    "delivery": {"en": "Delivery", "th": "การส่งมอบ"},
    "exploitation": {"en": "Exploitation", "th": "การโจมตี"},
    "installation": {"en": "Installation", "th": "การติดตั้ง"},
    "command_control": {"en": "Command & Control", "th": "การควบคุม"},
    "actions_objectives": {"en": "Actions on Objectives", "th": "การดำเนินการ"}
}

# Model parameters
MODEL_PARAMS = {
    "n_estimators": 200,
    "max_depth": 6,
    "learning_rate": 0.1,
    "objective": "multi:softmax",
    "eval_metric": "mlogloss",
    "random_state": 42,
    "n_jobs": -1
}

# Feature engineering
MAX_TFIDF_FEATURES = 100
FEATURE_COLUMNS_ORDER = []  # Will be populated during training

# Data sampling
TRAIN_SIZE = 0.8
TEST_SIZE = 0.2
RANDOM_STATE = 42

# Class imbalance handling
USE_SMOTE = True
SMOTE_K_NEIGHBORS = 5