import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/ping")
def ping():
    target = request.args.get("target", "127.0.0.1")

    process = subprocess.run(
        ["ping", "-c", "1", target],
        capture_output=True,
        text=True,
        shell=False  
    )

    return f"<pre>{process.stdout}</pre>"

if __name__ == "__main__":
    app.run(debug=False)
