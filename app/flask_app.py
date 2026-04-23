# flask_app.py
from flask import Flask, request, render_template, jsonify
from phish_utils import heuristic_features, vt_lookup, phishtank_lookup
from ml_model import predict_with_model, train_on_dataset
import os

app = Flask(__name__)

# Using templates/index.html now

@app.route("/", methods=["GET"])
def index():
    return render_template('index.html')

@app.route("/analyze", methods=["POST"])
def analyze():
    url = request.form.get("url")
    if not url:
        return "URL required", 400
    heur = heuristic_features(url)
    ml = predict_with_model(url)
    vt_ok, vt = vt_lookup(url)
    pt_ok, pt = phishtank_lookup(url)
    return render_template('index.html', result={
        "url": url,
        "score": heur["score"],
        "reasons": heur["reasons"],
        "features": heur["features"],
        "ml": ml,
        "vt": vt if vt_ok else vt,
        "pt": pt if pt_ok else pt
    })

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.json or {}
    url = data.get("url")
    if not url:
        return jsonify({"error":"url required"}), 400
    heur = heuristic_features(url)
    ml = predict_with_model(url)
    vt_ok, vt = vt_lookup(url)
    pt_ok, pt = phishtank_lookup(url)
    return jsonify({"url": url, "heuristic": heur, "ml": ml, "vt": vt if vt_ok else vt, "phishtank": pt if pt_ok else pt})

@app.route("/train", methods=["POST"])
def train():
    csv_path = request.form.get("csv")  # optional: path on server
    res = train_on_dataset(csv_path) 
    return jsonify(res)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))