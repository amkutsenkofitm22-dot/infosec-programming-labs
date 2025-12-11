import os
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/ping")
def ping():
    target = request.args.get("target", "127.0.0.1")
    result = os.popen(f"ping -c 1 {target}").read()
    return f"<pre>{result}</pre>"

@app.route("/save")
def save():
    data = request.args.get("data", "empty")
    with open("data.txt", "w") as f:
        f.write(data) 
    return "OK"

if __name__ == "__main__":
    app.run(debug=True)
