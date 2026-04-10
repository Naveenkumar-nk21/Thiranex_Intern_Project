def calculate_score(rule_results, issues):
    """Calculate password score out of 100."""
    score = 0

    # Positive scoring
    if rule_results["min_8"]:
        score += 15

    if rule_results["min_12"]:
        score += 10

    if rule_results["has_uppercase"]:
        score += 10

    if rule_results["has_lowercase"]:
        score += 10

    if rule_results["has_digit"]:
        score += 10

    if rule_results["has_special_character"]:
        score += 15

    if "Common password" not in issues and "Simple sequence" not in issues and "Keyboard pattern" not in issues:
        score += 10

    if "Repeated characters" not in issues:
        score += 10

    if len(set([
        rule_results["has_uppercase"],
        rule_results["has_lowercase"],
        rule_results["has_digit"],
        rule_results["has_special_character"]
    ])) > 1:
        score += 10

    # Negative scoring
    if "Common password" in issues:
        score -= 30

    if "Contains username/name" in issues:
        score -= 15

    if "Repeated characters" in issues:
        score -= 10

    if "Simple sequence" in issues:
        score -= 10

    if "Only letters or only digits" in issues:
        score -= 15

    # Clamp score
    score = max(0, min(score, 100))

    return score


def classify_strength(score):
    """Classify password based on score."""
    if 0 <= score <= 39:
        return "Weak"
    elif 40 <= score <= 69:
        return "Medium"
    return "Strong"