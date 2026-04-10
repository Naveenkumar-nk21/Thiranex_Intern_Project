from flask import Flask, render_template, request
from src.model_training import train_and_save_models
from src.predictor import load_saved_artifacts, predict_email_text
from src.utils import ensure_directories

app = Flask(__name__)

ensure_directories()

# Train once if model files are missing
try:
    model, vectorizer, scaler, feature_columns = load_saved_artifacts()
except FileNotFoundError:
    train_and_save_models()
    model, vectorizer, scaler, feature_columns = load_saved_artifacts()


@app.route("/", methods=["GET", "POST"])
def index():
    prediction = None
    probability = None
    metrics = None
    email_text = ""
    comparison = None

    if request.method == "POST":
        email_text = request.form.get("email_text", "").strip()
        action = request.form.get("action", "predict")

        if action == "train":
            metrics = train_and_save_models()
            global model, vectorizer, scaler, feature_columns
            model, vectorizer, scaler, feature_columns = load_saved_artifacts()
        elif email_text:
            prediction, probability = predict_email_text(
                email_text,
                model,
                vectorizer,
                scaler,
                feature_columns,
            )

    return render_template(
        "index.html",
        prediction=prediction,
        probability=probability,
        metrics=metrics,
        email_text=email_text,
    )


if __name__ == "__main__":
    app.run(debug=True)