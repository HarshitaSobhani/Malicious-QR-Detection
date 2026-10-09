import joblib
from app.ai.feature_extractor import extract_features

model = joblib.load("models/url_model.pkl")

def ai_score(url: str):
    features = extract_features(url)
    return float(model.predict_proba([features])[0][1])