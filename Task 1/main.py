from checker import run_rule_checks
from patterns import detect_patterns
from scorer import calculate_score, classify_strength
from suggestions import generate_suggestions, generate_sample_passwords
from history import check_reuse, add_password


def get_passed_checks(rule_results):
    passed = []

    if rule_results["min_8"]:
        passed.append("Length is at least 8 characters")

    if rule_results["min_12"]:
        passed.append("Length is at least 12 characters")

    if rule_results["has_uppercase"]:
        passed.append("Contains uppercase letter")

    if rule_results["has_lowercase"]:
        passed.append("Contains lowercase letter")

    if rule_results["has_digit"]:
        passed.append("Contains number")

    if rule_results["has_special_character"]:
        passed.append("Contains special character")

    return passed


def get_failed_checks(rule_results):
    failed = []

    if not rule_results["min_8"]:
        failed.append("Length is less than 8 characters")

    if not rule_results["min_12"]:
        failed.append("Length is less than 12 characters")

    if not rule_results["has_uppercase"]:
        failed.append("Missing uppercase letter")

    if not rule_results["has_lowercase"]:
        failed.append("Missing lowercase letter")

    if not rule_results["has_digit"]:
        failed.append("Missing number")

    if not rule_results["has_special_character"]:
        failed.append("Missing special character")

    return failed


def print_list(title, items):
    print(f"\n{title}:")
    if items:
        for item in items:
            print(f"- {item}")
    else:
        print("- None")


def main():
    while True:
        print("\n========== Password Strength Analyzer ==========")

        username = input("Enter your name/username (optional): ").strip()
        password = input("Enter password: ").strip()

        if not password:
            print("Password cannot be empty.")
            continue

        rule_results = run_rule_checks(password)
        issues = detect_patterns(password, username)
        score = calculate_score(rule_results, issues)
        strength = classify_strength(score)
        suggestions = generate_suggestions(rule_results, issues)
        sample_passwords = generate_sample_passwords()

        print(f"\nPassword Score: {score}/100")
        print(f"Strength Level: {strength}")

        print_list("Passed Checks", get_passed_checks(rule_results))
        print_list("Failed Checks", get_failed_checks(rule_results))
        print_list("Detected Issues", issues)
        print_list("Suggestions", suggestions)
        print_list("Sample Strong Password Ideas", sample_passwords)

        # SQLite password reuse check
        if check_reuse(password):
            print("\nWarning: This password was already used before. Please choose a new password.")
        else:
            add_password(password)
            print("\nPassword hash stored securely in SQLite database.")

        print("===============================================")

        choice = input("\nDo you want to test another password? (yes/no): ").strip().lower()
        if choice != "yes":
            print("Exiting Password Strength Analyzer. Stay secure!")
            break


if __name__ == "__main__":
    main()