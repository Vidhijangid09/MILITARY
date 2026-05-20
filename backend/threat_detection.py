import pandas as pd
import numpy as np
import joblib
from backend import db
import config
from sklearn.ensemble import IsolationForest
from backend.utils import make_audit_record

alerts = db['threat_alerts']

# Load or train the anomaly detection model used for intrusion prediction.
try:
    loaded = joblib.load(config.THREAT_MODEL_PATH)
    model = loaded.get('model') if isinstance(loaded, dict) else loaded
    scaler = loaded.get('scaler') if isinstance(loaded, dict) else None
except Exception:
    model = None
    scaler = None

# Detect intrusion from an event payload using the trained Isolation Forest model.
def detect_intrusion(event: dict) -> dict:
    global model, scaler
    if model is None or scaler is None:
        return {'success': False, 'message': 'Threat model is unavailable'}
    # Convert event payload into feature vector using expected numeric fields.
    numeric_fields = [
        'duration', 'src_bytes', 'dst_bytes', 'count', 'srv_count',
        'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate'
    ]
    sample = [float(event.get(field, 0)) for field in numeric_fields]
    processed = scaler.transform([sample]) if scaler is not None else [sample]
    prediction = model.predict(processed)[0]
    score = model.decision_function(processed)[0]
    is_anomaly = prediction == -1
    alert = {
        'event': event,
        'anomaly': bool(is_anomaly),
        'score': float(score),
        'timestamp': __import__('datetime').datetime.utcnow(),
    }
    if is_anomaly:
        alerts.insert_one(alert)
        db['audit_logs'].insert_one(make_audit_record('threat_detected', event.get('source', 'unknown'), 'Suspicious network activity flagged', event.get('source_ip')))
    return {'success': True, 'anomaly': bool(is_anomaly), 'score': float(score), 'message': 'Intrusion detected' if is_anomaly else 'Traffic appears normal'}

# Analyze traffic rows and return aggregated threat patterns.
def analyze_traffic(rows: list) -> list:
    output = []
    for row in rows:
        result = detect_intrusion(row)
        output.append({**row, 'anomaly': result.get('anomaly'), 'score': result.get('score')})
    return output

# Refresh model if new training data is available and persist it.
def update_model(new_model: IsolationForest, new_scaler) -> None:
    global model, scaler
    model = new_model
    scaler = new_scaler
    joblib.dump({'model': model, 'scaler': scaler}, config.THREAT_MODEL_PATH)
