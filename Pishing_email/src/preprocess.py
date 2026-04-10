import re
import string


STOPWORDS = {
    "the", "is", "and", "to", "of", "a", "in", "for", "on", "by",
    "this", "that", "it", "be", "are", "was", "with", "your", "you"
}


def clean_text(text, remove_stopwords=False):
    text = text.lower()
    text = re.sub(r"http[s]?://\S+|www\.\S+", " URL ", text)
    text = text.translate(str.maketrans("", "", string.punctuation))
    text = re.sub(r"\s+", " ", text).strip()

    if remove_stopwords:
        words = [word for word in text.split() if word not in STOPWORDS]
        text = " ".join(words)

    return text