# Phishing Email Detection Model

## Objective
This project detects whether an email is **phishing** or **safe** using machine learning.
It uses:
- email text/content
- suspicious phishing keywords
- URL-related features
- structural features

## Features
- Load dataset from CSV
- Clean and preprocess email text
- Extract TF-IDF features
- Add phishing indicators such as URL count, suspicious words, @ in links, IP in URLs
- Train and compare:
  - Logistic Regression
  - Multinomial Naive Bayes
- Show:
  - Accuracy
  - Confusion Matrix
  - Classification Report
- Predict custom email text
- Interactive Flask web page

## Folder Structure

```text
phishing_email_detection/
│
├── app.py
├── main.py
├── requirements.txt
├── README.md
├── data/
├── models/
├── reports/
├── src/
├── templates/
└── static/