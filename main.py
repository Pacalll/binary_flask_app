import os
import binary_analysis
from flask import Flask, request, render_template, jsonify
from flask_cors import CORS

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "./uploads"
CORS(app)

@app.route("/")
def start_page():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "file uploaded successfully" })
    file = request.files['file']
    if file.filename == '':
        return "error: no selected file"
    file.save(os.path.join(app.config["UPLOAD_FOLDER"], file.filename))
    print(binary_analysis.run_binary_analysis_rabin2(file))
    return jsonify({"message": "file uploaded successfully" })

if __name__ == "__main__":
    app.run(debug=True)