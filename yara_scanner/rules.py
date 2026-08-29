import os
import re
import yara


def find_rule_files(rules_directory):
    rule_files = []

    for root, dirs, files in os.walk(rules_directory):
        for filename in files:
            if filename.lower().endswith((".yar", ".yara")):
                rule_files.append(
                    os.path.abspath(
                        os.path.join(root, filename)
                    )
                )

    return sorted(rule_files)


def find_includes(rule_file):
    includes = set()

    try:
        with open(
            rule_file,
            "r",
            encoding="utf-8"
        ) as file:
            source = file.read()

    except (OSError, UnicodeDecodeError):
        return includes

    pattern = r'include\s+["\']([^"\']+)["\']'

    for match in re.finditer(
        pattern,
        source,
        re.IGNORECASE
    ):
        requested_file = match.group(1)

        include_path = os.path.abspath(
            os.path.join(
                os.path.dirname(rule_file),
                requested_file
            )
        )

        includes.add(include_path)

    return includes


def find_dependencies(rule_files):
    dependencies = set()
    pending = list(rule_files)
    checked = set()

    while pending:
        rule_file = os.path.abspath(
            pending.pop()
        )

        if rule_file in checked:
            continue

        checked.add(rule_file)

        includes = find_includes(rule_file)

        for include_file in includes:
            if include_file in dependencies:
                continue

            dependencies.add(include_file)

            if os.path.isfile(include_file):
                pending.append(include_file)

    return dependencies


def include_callback(
    requested_file,
    filename,
    namespace
):
    try:
        include_path = os.path.abspath(
            os.path.join(
                os.path.dirname(filename),
                requested_file
            )
        )

        with open(
            include_path,
            "r",
            encoding="utf-8"
        ) as file:
            return file.read()

    except (OSError, UnicodeDecodeError) as error:
        raise yara.Error(
            f"Failed to include "
            f"'{requested_file}': {error}"
        )


def compile_rules(rule_files):
    rules = []
    errors = []

    dependencies = find_dependencies(
        rule_files
    )

    standalone_files = [
        rule_file
        for rule_file in rule_files
        if rule_file not in dependencies
    ]

    for rule_file in standalone_files:
        try:
            compiled = yara.compile(
                filepath=rule_file,
                include_callback=include_callback
            )

            rules.append({
                "compiled": compiled,
                "file": rule_file
            })

        except (
            OSError,
            UnicodeDecodeError,
            yara.Error
        ) as error:

            errors.append({
                "file": rule_file,
                "error": str(error)
            })

    return rules, errors


def count_rules(rules):
    count = 0

    for rule_set in rules:
        for rule in rule_set["compiled"]:
            count += 1

    return count