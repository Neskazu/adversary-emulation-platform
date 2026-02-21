import os
import sys

# Third-party dependency check
try:
    import yaml
except ImportError:
    print("Error: PyYAML is not installed. Run 'pip install pyyaml'")
    sys.exit(1)


# ANSI color codes for terminal output formatting
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"


def check_yaml_syntax(file_path):
    """Validate YAML syntax for all documents inside a file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            list(yaml.safe_load_all(f))
        return True, None
    except yaml.YAMLError as exc:
        return False, str(exc)


def validate_sigma_rule(content):
    """Perform minimal structural validation of a Sigma rule."""
    required_fields = ["title", "id", "status", "logsource", "detection", "level"]
    errors = []

    for field in required_fields:
        if field not in content:
            errors.append(f"Missing required field: {field}")

    if isinstance(content.get("logsource"), dict):
        logsource = content["logsource"]
        if "product" not in logsource and "category" not in logsource:
            errors.append("Logsource must contain 'product' or 'category'")
    else:
        errors.append("Logsource must be a dictionary")

    if isinstance(content.get("detection"), dict):
        if "condition" not in content["detection"]:
            errors.append("Detection must contain 'condition'")
    else:
        errors.append("Detection must be a dictionary")

    return errors


def is_sigma_candidate(content):
    """Determine whether a YAML document resembles a Sigma rule."""
    return (
        isinstance(content, dict)
        and "title" in content
        and "detection" in content
        and "logsource" in content
    )


def scan_directory(root_dir):
    """Recursively scan a directory for YAML syntax and Sigma validation errors."""
    print(f"Scanning directory: {root_dir}")
    has_errors = False

    excludes = {".vagrant", "venv", ".git"}

    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in excludes]

        for file in files:
            if not file.endswith((".yml", ".yaml")):
                continue

            full_path = os.path.join(root, file)
            relative_path = os.path.relpath(full_path, root_dir)

            valid, error = check_yaml_syntax(full_path)
            if not valid:
                print(f"{RED}[YAML ERROR]{RESET} {relative_path}: {error}")
                has_errors = True
                continue

            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    content = yaml.safe_load(f)

                if is_sigma_candidate(content):
                    sigma_errors = validate_sigma_rule(content)
                    if sigma_errors:
                        print(f"{RED}[SIGMA ERROR]{RESET} {relative_path}:")
                        for err in sigma_errors:
                            print(f"  - {err}")
                        has_errors = True

            except Exception as e:
                print(f"{RED}[INTERNAL ERROR]{RESET} {relative_path}: {e}")
                has_errors = True

    if not has_errors:
        print(f"{GREEN}No linting errors found.{RESET}")
    else:
        print(f"{RED}Errors found.{RESET}")
        sys.exit(1)


if __name__ == "__main__":
    project_root = os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
    scan_directory(project_root)