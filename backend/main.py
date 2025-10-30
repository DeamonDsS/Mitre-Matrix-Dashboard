# main.py
from fastapi import FastAPI
import joblib
from ml.utils.feature_engineering import extract_features

app = FastAPI()
model_bundle = None

@app.on_event("startup")
async def load_model_on_startup():
    global model_bundle
    model_bundle = joblib.load("ml/models/killchain_xgb.pkl")
    print("✅ CKC Model loaded")

@app.post("/predict_phase")
async def predict_phase(logs: list[dict]):
    if model_bundle is None:
        return {"error": "Model not loaded"}

    features = extract_features(logs)
    preds = model_bundle["model"].predict(features)
    phases = model_bundle["phases"]
    result = [phases[int(i)] for i in preds]
    return {"predictions": result}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )

