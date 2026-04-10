import pandas as pd

# Load Kaggle dataset
df = pd.read_csv("dataset1.csv")

# Combine subject + body
df["text"] = df["subject"] + " " + df["body"]

# Convert label
df["label"] = df["label"].map({1: "phishing", 0: "safe"})

# Keep only required columns
df = df[["text", "label"]]

# Save to project format
df.to_csv("data/emails.csv", index=False)

print("Dataset converted successfully!")