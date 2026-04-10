import os
import matplotlib.pyplot as plt
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report, ConfusionMatrixDisplay


def evaluate_models(logistic_model, nb_model, x_test, y_test):
    logistic_preds = logistic_model.predict(x_test)
    nb_preds = nb_model.predict(x_test)

    logistic_accuracy = accuracy_score(y_test, logistic_preds)
    nb_accuracy = accuracy_score(y_test, nb_preds)

    best_preds = logistic_preds if logistic_accuracy >= nb_accuracy else nb_preds
    best_confusion_matrix = confusion_matrix(y_test, best_preds)
    best_report = classification_report(y_test, best_preds, target_names=["safe", "phishing"])

    os.makedirs("reports", exist_ok=True)

    disp = ConfusionMatrixDisplay(confusion_matrix=best_confusion_matrix, display_labels=["safe", "phishing"])
    fig, ax = plt.subplots(figsize=(5, 5))
    disp.plot(ax=ax)
    plt.title("Confusion Matrix")
    plt.savefig("reports/confusion_matrix.png", bbox_inches="tight")
    plt.close(fig)

    return {
        "logistic_regression_accuracy": logistic_accuracy,
        "naive_bayes_accuracy": nb_accuracy,
        "classification_report": best_report,
        "confusion_matrix": best_confusion_matrix.tolist(),
    }


def save_metrics_report(metrics):
    with open("reports/metrics.txt", "w", encoding="utf-8") as file:
        file.write("PHISHING EMAIL DETECTION METRICS\n")
        file.write("=" * 50 + "\n")
        file.write(f"Logistic Regression Accuracy: {metrics['logistic_regression_accuracy']:.4f}\n")
        file.write(f"Naive Bayes Accuracy: {metrics['naive_bayes_accuracy']:.4f}\n")
        file.write(f"Best Model: {metrics['best_model_name']}\n\n")
        file.write("Classification Report:\n")
        file.write(metrics["classification_report"])
        file.write("\nConfusion Matrix:\n")
        file.write(str(metrics["confusion_matrix"]))