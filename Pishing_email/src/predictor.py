import joblib
from src.preprocess import clean_text
from src.feature_extraction import extract_handcrafted_features, transform_text, combine_features


MODEL_PATH = "models/phishing_model.pkl"
VECTORIZER_PATH = "models/tfidf_vectorizer.pkl"
SCALER_PATH = "models/scaler.pkl"
FEATURE_COLUMNS_PATH = "models/feature_columns.pkl"


def load_saved_artifacts():
    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    scaler = joblib.load(SCALER_PATH)
    feature_columns = joblib.load(FEATURE_COLUMNS_PATH)
    return model, vectorizer, scaler, feature_columns


def predict_email_text(email_text, model, vectorizer, scaler, feature_columns):
    clean_email = clean_text(email_text)
    tfidf_features = transform_text(vectorizer, [clean_email])

    handcrafted_df = extract_handcrafted_features([email_text])
    handcrafted_df = handcrafted_df[feature_columns]
    handcrafted_df[feature_columns] = scaler.transform(handcrafted_df)

    final_features = combine_features(tfidf_features, handcrafted_df)

    prediction_num = model.predict(final_features)[0]

    if hasattr(model, "predict_proba"):
        probability = model.predict_proba(final_features)[0][prediction_num] * 100
    else:
        probability = 0.0

    prediction_label = "Phishing" if prediction_num == 1 else "Safe"
    return prediction_label, probability