from src.model_training import train_and_save_models
from src.predictor import load_saved_artifacts, predict_email_text


def main():
    print("=" * 60)
    print("PHISHING EMAIL DETECTION SYSTEM")
    print("=" * 60)

    print("\nTraining model...")
    metrics = train_and_save_models()

    print("\nModel Performance")
    print(f"Logistic Regression Accuracy: {metrics['logistic_regression_accuracy']:.4f}")
    print(f"Naive Bayes Accuracy: {metrics['naive_bayes_accuracy']:.4f}")
    print(f"Best Model Selected: {metrics['best_model_name']}")

    model, vectorizer, scaler, feature_columns = load_saved_artifacts()

    while True:
        print("\nEnter an email text to predict.")
        print("Type 'exit' to stop.")
        email_text = input("\nEmail: ").strip()

        if email_text.lower() == "exit":
            print("Exiting program.")
            break

        if not email_text:
            print("Please enter some email text.")
            continue

        prediction, probability = predict_email_text(
            email_text,
            model,
            vectorizer,
            scaler,
            feature_columns,
        )

        print(f"Prediction: {prediction}")
        print(f"Confidence: {probability:.2f}%")


if __name__ == "__main__":
    main()