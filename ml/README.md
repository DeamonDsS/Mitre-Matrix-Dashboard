"""
# Cyber Kill Chain ML Pipeline

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Configure Elasticsearch:
Edit `ml/config.py` and set:
- ES_HOST
- ES_USERNAME
- ES_PASSWORD
- ES_INDEX_PATTERN

## Usage

### 1. Prepare Dataset
```bash
cd ml/train
python prepare_dataset.py
```

This will:
- Fetch logs from Elasticsearch
- Apply heuristic labels (replace with real labels!)
- Extract features
- Balance classes
- Save to `ml/data/training_data_*.pkl`

### 2. Train Model
```bash
python train_model.py

# With hyperparameter tuning
python train_model.py --tune

# Using existing data file
python train_model.py --data ../data/training_data_20251030_120000.pkl
```

This will:
- Load or prepare dataset
- Apply SMOTE for class balancing
- Train XGBoost model
- Perform cross-validation
- Generate evaluation plots
- Save model to `ml/models/killchain_xgb_*.pkl`

### 3. Evaluate Model
```bash
cd ml
python evaluate_model.py --model models/killchain_xgb_20251030_120000.pkl
```

### 4. Start API Server
```bash
cd ml
python ml_api.py
```

API will be available at http://localhost:8000

Endpoints:
- POST /api/ml/predict-killchain - Get predictions
- GET /api/ml/model-info - Model metadata
- GET /health - Health check

### 5. Test API
```bash
curl -X POST http://localhost:8000/api/ml/predict-killchain \
  -H "Content-Type: application/json" \
  -d '{
    "indices": ["logs-*"],
    "day_range": 7,
    "confidence_threshold": 0.6
  }'
```

## Directory Structure
```
ml/
├── config.py              # Configuration
├── ml_api.py             # FastAPI service
├── evaluate_model.py     # Model evaluation
├── requirements.txt      # Dependencies
├── utils/
│   └── feature_engineering.py  # Feature extraction
├── train/
│   ├── prepare_dataset.py      # Dataset preparation
│   └── train_model.py          # Model training
├── models/               # Saved models
├── data/                 # Training data
└── logs/                 # Training logs & plots
```

## Important Notes

⚠️ **CRITICAL**: The current implementation uses heuristic labeling which is NOT suitable for production!

For production use:
1. Collect real labeled data from security analysts
2. Use MITRE ATT&CK mappings for ground truth
3. Implement human-in-the-loop labeling
4. Regularly retrain with new data

## Model Performance Tips

1. **Feature Engineering**: Add more domain-specific features
2. **Data Quality**: Get real labeled incidents
3. **Ensemble Methods**: Combine multiple models
4. **Continuous Learning**: Retrain monthly with new data
5. **Explainability**: Use SHAP values to understand predictions

## Monitoring

Track these metrics in production:
- Prediction confidence distribution
- Phase distribution over time
- False positive rate
- Analyst feedback
- Model drift

## Contributing

When improving the model:
1. Document feature additions
2. Track model versions
3. Compare against baseline
4. A/B test in production
"""