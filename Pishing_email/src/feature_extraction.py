import re
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack, csr_matrix


SUSPICIOUS_WORDS = [
    "urgent", "verify", "click", "login", "password", "account", "bank",
    "update", "reset", "limited", "confirm", "security", "alert", "suspend"
]

SHORTENERS = ["bit.ly", "tinyurl", "goo.gl", "t.co"]


def count_urls(text):
    urls = re.findall(r"http[s]?://\S+|www\.\S+|bit\.ly/\S+|tinyurl\.com/\S+", text.lower())
    return len(urls)


def has_ip_in_url(text):
    return int(re.search(r"http[s]?://(?:\d{1,3}\.){3}\d{1,3}", text.lower()) is not None)


def suspicious_keyword_count(text):
    text_lower = text.lower()
    return sum(word in text_lower for word in SUSPICIOUS_WORDS)


def has_at_symbol(text):
    return int("@" in text)


def has_http(text):
    return int("http" in text.lower() or "www" in text.lower())


def has_shortened_url(text):
    text_lower = text.lower()
    return int(any(shortener in text_lower for shortener in SHORTENERS))


def special_character_count(text):
    return sum(1 for char in text if not char.isalnum() and not char.isspace())


def exclamation_count(text):
    return text.count("!")


def all_caps_word_count(text):
    words = text.split()
    return sum(1 for word in words if len(word) > 1 and word.isupper())


def digit_count(text):
    return sum(1 for char in text if char.isdigit())


def extract_handcrafted_features(texts):
    feature_rows = []

    for text in texts:
        feature_rows.append({
            "url_count": count_urls(text),
            "contains_ip_url": has_ip_in_url(text),
            "suspicious_keyword_count": suspicious_keyword_count(text),
            "contains_at_symbol": has_at_symbol(text),
            "contains_http": has_http(text),
            "contains_shortener": has_shortened_url(text),
            "special_character_count": special_character_count(text),
            "exclamation_count": exclamation_count(text),
            "all_caps_word_count": all_caps_word_count(text),
            "digit_count": digit_count(text),
        })

    return pd.DataFrame(feature_rows)


def fit_vectorizer(train_texts):
    vectorizer = TfidfVectorizer(max_features=3000, ngram_range=(1, 2))
    x_train_tfidf = vectorizer.fit_transform(train_texts)
    return vectorizer, x_train_tfidf


def transform_text(vectorizer, texts):
    return vectorizer.transform(texts)


def combine_features(tfidf_matrix, handcrafted_df):
    handcrafted_sparse = csr_matrix(handcrafted_df.values)
    return hstack([tfidf_matrix, handcrafted_sparse])