from flask import Flask, render_template, request
import sys
import os

# Allow importing files from parent folder
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from checker import run_rule_checks
from patterns import detect_patterns
from scorer import calculate_score, classify_strength
from suggestions import generate_suggestions, generate_sample_passwords
from history import check_reuse, add_password

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if password:
            rule_results = run_rule_checks(password)
            issues = detect_patterns(password, username)
            score = calculate_score(rule_results, issues)
            strength = classify_strength(score)
            suggestions = generate_suggestions(rule_results, issues)
            samples = generate_sample_passwords()

            reused = check_reuse(password)

            if reused:
                reuse_message = "Warning: This password was already used before. Please choose a new password."
            else:
                add_password(password)
                reuse_message = "Password hash stored securely in SQLite database."

            result = {
                "score": score,
                "strength": strength,
                "issues": issues,
                "suggestions": suggestions,
                "samples": samples,
                "reuse_message": reuse_message
            }

    return render_template("index.html", result=result)


if __name__ == "__main__":
    print("Starting Flask server...")
    app.run(debug=True)