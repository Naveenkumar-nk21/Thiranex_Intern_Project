import random

WORDS_1 = ["Sky", "Blue", "Study", "Moon", "River", "Train", "Cloud"]
WORDS_2 = ["Tiger", "Stone", "Light", "Bridge", "Star", "Power", "Dream"]
SYMBOLS = ["!", "@", "#", "$", "_"]
NUMBERS = ["27", "48", "92", "2026", "84"]


def generate_suggestions(rule_results, issues):
    """Generate improvement suggestions."""
    suggestions = []

    if not rule_results["min_8"]:
        suggestions.append("Increase password length to at least 8 characters.")

    if not rule_results["min_12"]:
        suggestions.append("Use at least 12 characters for better security.")

    if not rule_results["has_uppercase"]:
        suggestions.append("Add uppercase letters.")

    if not rule_results["has_lowercase"]:
        suggestions.append("Add lowercase letters.")

    if not rule_results["has_digit"]:
        suggestions.append("Include numbers.")

    if not rule_results["has_special_character"]:
        suggestions.append("Include special characters like !, @, #, $.")

    if "Common password" in issues:
        suggestions.append("Avoid common passwords like password, admin, or 123456.")

    if "Contains common word" in issues:
        suggestions.append("Avoid using simple dictionary/common words.")

    if "Repeated characters" in issues:
        suggestions.append("Avoid repeated characters like aaaa or 1111.")

    if "Simple sequence" in issues:
        suggestions.append("Avoid sequences like 1234 or abcd.")

    if "Keyboard pattern" in issues:
        suggestions.append("Avoid keyboard patterns like qwerty or asdf.")

    if "Year pattern" in issues:
        suggestions.append("Avoid using birth year or common years.")

    if "Contains username/name" in issues:
        suggestions.append("Do not include your username or personal name in the password.")

    if "Only letters or only digits" in issues:
        suggestions.append("Mix letters, numbers, and symbols for better strength.")

    if not suggestions:
        suggestions.append("Your password looks good. Keep it safe and unique.")

    return suggestions


def generate_sample_passwords():
    """Generate 3 strong sample passwords."""
    samples = []

    for _ in range(3):
        password = (
            random.choice(WORDS_1) +
            random.choice(WORDS_2) +
            random.choice(SYMBOLS) +
            random.choice(NUMBERS)
        )
        samples.append(password)

    return samples