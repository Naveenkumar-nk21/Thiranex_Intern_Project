import string


def check_length(password):
    """Check password length conditions."""
    return {
        "min_8": len(password) >= 8,
        "min_12": len(password) >= 12,
        "length": len(password)
    }


def has_uppercase(password):
    """Check if password contains uppercase letter."""
    return any(char.isupper() for char in password)


def has_lowercase(password):
    """Check if password contains lowercase letter."""
    return any(char.islower() for char in password)


def has_digit(password):
    """Check if password contains digit."""
    return any(char.isdigit() for char in password)


def has_special_character(password):
    """Check if password contains special character."""
    special_chars = string.punctuation
    return any(char in special_chars for char in password)


def run_rule_checks(password):
    """Run all basic password rule checks."""
    length_info = check_length(password)

    results = {
        "length": length_info["length"],
        "min_8": length_info["min_8"],
        "min_12": length_info["min_12"],
        "has_uppercase": has_uppercase(password),
        "has_lowercase": has_lowercase(password),
        "has_digit": has_digit(password),
        "has_special_character": has_special_character(password)
    }

    return results