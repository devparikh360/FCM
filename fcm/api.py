# file: api.py
from flask import Flask, request, jsonify
from flask_cors import CORS

# Import detection functions from your engine
from detection.engine import score_url, score_content, score_app  

app = Flask(__name__)
CORS(app)


# --- Detect URL ---
@app.route("/detect/url", methods=["POST"])
def detect_url():
    data = request.get_json()
    url = data.get("url")
    if not url:
        return jsonify({"error": "Missing 'url'"}), 400
    
    result = score_url(url)   # Calls detection engine
    return jsonify({"url": url, "result": result})


# --- Detect Text Content ---
@app.route("/detect/content", methods=["POST"])
def detect_content():
    data = request.get_json()
    content = data.get("content")
    if not content:
        return jsonify({"error": "Missing 'content'"}), 400
    
    result = score_content(content)   # Calls detection engine
    return jsonify({"content": content, "result": result})


# --- Detect App Metadata ---
@app.route("/detect/app", methods=["POST"])
def detect_app():
    data = request.get_json()
    app_info = data.get("app_info")
    if not app_info:
        return jsonify({"error": "Missing 'app_info'"}), 400
    
    result = score_app(app_info)   # Calls detection engine
    return jsonify({"app_info": app_info, "result": result})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
