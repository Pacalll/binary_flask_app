import os
import binary_analysis
from flask import Flask, request, render_template, jsonify

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "./uploads"

@app.route("/", methods=["GET"])
def start_page():
    rabin2 = binary_analysis.get_binary_analysis("binary_info_rabin2")
    strace = binary_analysis.get_binary_analysis("binary_info_strace")
    strings = binary_analysis.get_binary_analysis("binary_info_strings")
    libs = binary_analysis.get_binary_analysis("library")
    syscall_images = [f for f in os.listdir("static") if f.startswith("syscall_overview_image")]
    return render_template("index.html",
                           rabin2=rabin2,
                           strace=strace,
                           strings=strings,
                           libs=libs,
                           syscall_images=syscall_images)
@app.route("/upload", methods=["POST"])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "file not uploaded successfully" })
    file = request.files['file']
    if file.filename == '':
        return "error: no selected file"
    file.save(os.path.join(app.config["UPLOAD_FOLDER"], file.filename))
    binary_analysis.run_binary_analysis(file)
    return jsonify({"message": "file uploaded successfully"})

if __name__ == "__main__":
    app.run(debug=True)