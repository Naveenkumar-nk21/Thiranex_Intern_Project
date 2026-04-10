import re

COMMON_PASSWORDS = [
    "password", "123456", "12345678", "admin", "qwerty",
    "letmein", "welcome", "iloveyou", "abc123", "password123"
]

COMMON_WORDS = [
    "hello", "love", "study", "god", "india", "test",
    "login", "user", "name", "naveen", "college"
]

KEYBOARD_PATTERNS = [
    "qwerty", "asdf", "zxcv", "qaz", "wsx"
]


def detect_common_password(password):
    """Check if password exactly matches a common password."""
    return password.lower() in COMMON_PASSWORDS


def detect_common_word(password):
    """Check if password contains common word."""
    password_lower = password.lower()
    for word in COMMON_WORDS:
        if word in password_lower:
            return True
    return False


def detect_repeated_characters(password):
    """Check repeated characters like aaaa or 1111."""
    return re.search(r"(.)\1{2,}", password) is not None


def detect_sequence(password):
    """Check simple sequences like 1234 or abcd."""
    password_lower = password.lower()

    sequences = [
        "0123456789",
        "123456789",
        "abcdefghijklmnopqrstuvwxyz"
    ]

    for seq in sequences:
        for i in range(len(seq) - 3):
            part = seq[i:i + 4]
            if part in password_lower:
                return True
    return False


def detect_keyboard_pattern(password):
    """Check keyboard patterns like qwerty or asdf."""
    password_lower = password.lower()
    for pattern in KEYBOARD_PATTERNS:
        if pattern in password_lower:
            return True
    return False


def detect_year_pattern(password):
    """Check year-style patterns like 2004, 2024."""
    years = [str(year) for year in range(1990, 2031)]
    for year in years:
        if year in password:
            return True
    return False


def detect_username_in_password(password, username):
    """Check if username is used in password."""
    if not username:
        return False
    return username.lower() in password.lower()


def detect_only_letters_or_digits(password):
    """Check if password contains only letters or only digits."""
    return password.isalpha() or password.isdigit()


def detect_patterns(password, username=""):
    """Return list of detected weak patterns."""
    issues = []

    if detect_common_password(password):
        issues.append("Common password")

    if detect_common_word(password):
        issues.append("Contains common word")

    if detect_repeated_characters(password):
        issues.append("Repeated characters")

    if detect_sequence(password):
        issues.append("Simple sequence")

    if detect_keyboard_pattern(password):
        issues.append("Keyboard pattern")

    if detect_year_pattern(password):
        issues.append("Year pattern")

    if detect_username_in_password(password, username):
        issues.append("Contains username/name")

    if detect_only_letters_or_digits(password):
        issues.append("Only letters or only digits")

    return issues