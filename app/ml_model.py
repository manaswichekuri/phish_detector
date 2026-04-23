# ml_model.py
import os
import joblib
import numpy as np
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from phish_utils import heuristic_features
import json

MODEL_PATH = "phish_model.joblib"

def extract_feature_vector(url):
    out = heuristic_features(url)
    f = out["features"]
    # ensure stable feature order
    vec = [
        f.get("is_ip",0),
        f.get("has_at",0),
        f.get("len_url",0),
        f.get("subdomain_count",0),
        f.get("hyphen_in_domain",0),
        f.get("is_shortener",0),
        f.get("is_https",0),
        f.get("susp_keyword",0),
        f.get("has_password_field",0),
        f.get("external_links_count",0),
        f.get("ssl_valid",0),
        f.get("domain_age_days", -1)
    ]
    # domain_age_days could be -1; replace with large number indicator
    if vec[-1] == -1:
        vec[-1] = 3650
    return np.array(vec, dtype=float)

def train_on_dataset(csv_path=None, save_path=MODEL_PATH):
    """
    csv_path (optional) - path to labeled CSV with two columns: url,label
    If no dataset provided, function generates a small synthetic dataset (for demo).
    """
    urls = []
    labels = []
    if csv_path and os.path.exists(csv_path):
        import csv
        with open(csv_path, newline='', encoding='utf-8') as fh:
            reader = csv.reader(fh)
            for row in reader:
                if not row: continue
                url = row[0].strip()
                label = int(row[1])
                urls.append(url)
                labels.append(label)
    else:
        # tiny synthetic dataset (demo) - expand with real labeled data
        sample = [
            ("https://example.com", 0),
            ("http://bit.ly/abcd", 1),
            ("http://192.168.1.5/login", 1),
            ("https://secure-paypal.example.com/login", 1),
            ("https://google.com", 0),
            ("http://mybank.example-login.com/verify", 1),
            ("https://github.com", 0)
        ]
        for u,l in sample:
            urls.append(u); labels.append(l)

    X = []
    for u in urls:
        X.append(extract_feature_vector(u))
    X = np.vstack(X)
    y = np.array(labels)

    X_train, X_test, y_train, y_test = train_test_split(X,y,test_size=0.2, random_state=42)
    pipe = Pipeline([
        ("scale", StandardScaler()),
        ("clf", LogisticRegression(max_iter=1000))
    ])
    pipe.fit(X_train, y_train)
    acc = pipe.score(X_test, y_test)
    joblib.dump(pipe, save_path)
    return {"accuracy": acc, "model_path": save_path}

def predict_with_model(url, model_path=MODEL_PATH):
    if not os.path.exists(model_path):
        return {"error": "model not found"}
    model = joblib.load(model_path)
    vec = extract_feature_vector(url).reshape(1,-1)
    prob = model.predict_proba(vec)[0,1] if hasattr(model, "predict_proba") else None
    label = int(model.predict(vec)[0])
    return {"label": label, "probability_phish": float(prob) if prob is not None else None}