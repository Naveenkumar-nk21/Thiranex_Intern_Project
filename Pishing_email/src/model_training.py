import joblib
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.preprocessing import MinMaxScaler

from src.data_loader import load_dataset
from src.preprocess import clean_text
from src.feature_extraction import (
    extract_handcrafted_features,
    fit_vectorizer,
    transform_text,
    combine_features,
)
from src.evaluation import evaluate_models, save_metrics_report
from src.utils import ensure_directories


MODEL_PATH = "models/phishing_model.pkl"
VECTORIZER_PATH = "models/tfidf_vectorizer.pkl"
SCALER_PATH = "models/scaler.pkl"
FEATURE_COLUMNS_PATH = "models/feature_columns.pkl"


def train_and_save_models():
    ensure_directories()

    # Load dataset
    df = load_dataset()

    # Clean text
    df["clean_text"] = df["text"].apply(clean_text)

    # Convert labels to numeric
    df["label_num"] = df["label"].map({"safe": 0, "phishing": 1})

    # Split data
    x_train, x_test, y_train, y_test = train_test_split(
        df["clean_text"],
        df["label_num"],
        test_size=0.2,
        random_state=42,
        stratify=df["label_num"],
    )

    # TF-IDF features
    vectorizer, x_train_tfidf = fit_vectorizer(x_train)
    x_test_tfidf = transform_text(vectorizer, x_test)

    # Handcrafted features
    train_handcrafted = extract_handcrafted_features(x_train)
    test_handcrafted = extract_handcrafted_features(x_test)

    # Scale handcrafted features
    scaler = MinMaxScaler()
    train_handcrafted_scaled = train_handcrafted.copy()
    test_handcrafted_scaled = test_handcrafted.copy()

    train_handcrafted_scaled[train_handcrafted.columns] = scaler.fit_transform(train_handcrafted)
    test_handcrafted_scaled[test_handcrafted.columns] = scaler.transform(test_handcrafted)

    # Combine TF-IDF + handcrafted features
    x_train_final = combine_features(x_train_tfidf, train_handcrafted_scaled)
    x_test_final = combine_features(x_test_tfidf, test_handcrafted_scaled)

    # Train models
    logistic_model = LogisticRegression(max_iter=1000)
    logistic_model.fit(x_train_final, y_train)

    nb_model = MultinomialNB()
    nb_model.fit(x_train_final, y_train)

    # Evaluate models
    metrics = evaluate_models(logistic_model, nb_model, x_test_final, y_test)

    # Select best model
    if metrics["logistic_regression_accuracy"] >= metrics["naive_bayes_accuracy"]:
        best_model = logistic_model
        best_model_name = "Logistic Regression"
    else:
        best_model = nb_model
        best_model_name = "Multinomial Naive Bayes"

    metrics["best_model_name"] = best_model_name

    # Save best model and preprocessing objects
    joblib.dump(best_model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(list(train_handcrafted.columns), FEATURE_COLUMNS_PATH)

    # Save metrics report
    save_metrics_report(metrics)

    return metrics