from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import pandas as pd
from sklearn.ensemble import IsolationForest
import numpy as np

app = FastAPI(title="WatchTower ML Scoring Service")

# Request Model
class FeatureVector(BaseModel):
    source_ip: str
    login_count_1h: int
    login_count_24h: int
    unique_ips_24h: int
    hour_of_day: int
    bytes_transferred: float

# Response Model
class ScoreResponse(BaseModel):
    anomaly_score: float
    is_anomaly: bool
    confidence: float

# Pre-trained dummy model for demonstration.
# In a real scenario, this would be loaded from a saved model artifact (.joblib or .pkl)
# trained on historical normal traffic.
dummy_model = IsolationForest(contamination=0.05, random_state=42)

# Fit the model on some synthetic "normal" baseline data
# Normal behavior: low login counts, few unique IPs, standard office hours
X_normal = pd.DataFrame({
    'login_count_1h': np.random.poisson(lam=1, size=1000),
    'login_count_24h': np.random.poisson(lam=10, size=1000),
    'unique_ips_24h': np.random.poisson(lam=1, size=1000),
    'hour_of_day': np.random.randint(9, 18, size=1000),  # 9 AM to 5 PM
    'bytes_transferred': np.random.normal(loc=5000, scale=1000, size=1000)
})
dummy_model.fit(X_normal)

@app.get("/health")
def health_check():
    return {"status": "up", "model": "IsolationForest (sklearn)"}

@app.post("/api/v1/score", response_model=ScoreResponse)
def score_event(features: FeatureVector):
    try:
        # Prepare data for prediction
        df = pd.DataFrame([{
            'login_count_1h': features.login_count_1h,
            'login_count_24h': features.login_count_24h,
            'unique_ips_24h': features.unique_ips_24h,
            'hour_of_day': features.hour_of_day,
            'bytes_transferred': features.bytes_transferred
        }])

        # Prediction: 1 for normal, -1 for anomaly
        prediction = dummy_model.predict(df)[0]
        
        # Decision function: lower values (negative) are more abnormal
        raw_score = dummy_model.decision_function(df)[0]
        
        # Convert raw_score to a 0.0-1.0 anomaly score
        # Since lower is more anomalous in sklearn, we invert it
        # Min-max scaling heuristic for demo purposes
        normalized_anomaly_score = float(1.0 / (1.0 + np.exp(raw_score * 5)))

        is_anomaly = bool(prediction == -1)
        
        # Confidence logic: further from the decision boundary = higher confidence
        confidence = float(min(abs(raw_score) * 2.0, 1.0))

        return ScoreResponse(
            anomaly_score=normalized_anomaly_score,
            is_anomaly=is_anomaly,
            confidence=confidence
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
