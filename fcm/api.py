# file: api.py
from flask import Flask, request, jsonify
from flask_cors import CORS

# Import your detection engine
from detection.engine import score_url  

app = Flask(__name__)
CORS(app)  # allow React dev server to call

@app.route("/detect/url", methods=["POST"])
def detect_url():
    data = request.get_json()
    url = data.get("url")
    if not url:
        return jsonify({"error": "Missing 'url'"}), 400

    # Call your trained model
    try:
        result = score_url(url)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"url": url, "result": result})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
