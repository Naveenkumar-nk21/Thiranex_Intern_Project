# Password Strength Analyzer

## Objective
This project is a beginner-friendly cybersecurity internship project that checks the strength of a password and gives feedback to improve it.

## Features
- Checks password length
- Checks uppercase, lowercase, digits, and special characters
- Detects common passwords
- Detects repeated characters
- Detects simple sequences like 1234 or abcd
- Detects keyboard patterns like qwerty
- Detects year-style patterns
- Detects username/name inside password
- Gives score out of 100
- Classifies password as Weak / Medium / Strong
- Suggests improvements
- Generates strong sample passwords
- Optional password history using SHA-256 hashing

## Project Modules
- `checker.py` → checks basic password rules
- `patterns.py` → detects weak patterns
- `scorer.py` → calculates score and strength level
- `suggestions.py` → provides suggestions and strong examples
- `history.py` → stores old password hashes securely
- `main.py` → command-line interface

## Technologies Used
- Python
- JSON
- hashlib
- Flask (optional web version)

## How It Works
1. User enters username/name (optional)
2. User enters password
3. Program checks rules and weak patterns
4. Program calculates score
5. Program displays strength level
6. Program gives suggestions
7. Program optionally stores password hash to prevent reuse

## Scoring Method
### Positive Score
- length >= 8 → +15
- length >= 12 → +10
- uppercase → +10
- lowercase → +10
- digit → +10
- special character → +15

### Negative Score
- common password → -30
- repeated characters → -10
- sequence → -10
- only letters or digits → -15

## How to Run
```bash
python main.py