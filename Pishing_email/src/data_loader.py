import pandas as pd


REQUIRED_COLUMNS = ["text", "label"]


def load_dataset(file_path="data/emails.csv"):
    df = pd.read_csv(file_path)

    missing_columns = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing_columns:
        raise ValueError(f"Dataset must contain columns: {REQUIRED_COLUMNS}")

    df = df.dropna(subset=["text", "label"])
    df["text"] = df["text"].astype(str)
    df["label"] = df["label"].astype(str).str.lower().str.strip()
    df = df[df["label"].isin(["phishing", "safe"])]

    return df