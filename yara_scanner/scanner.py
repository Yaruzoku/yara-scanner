import hashlib
import math
import mimetypes
import os
import time


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(
            lambda: f.read(1024 * 1024),
            b""
        ):
            sha256.update(chunk)

    return sha256.hexdigest()


def calculate_entropy(file_path):
    with open(file_path, "rb") as f:
        data = f.read()

    if not data:
        return 0.0

    frequencies = [0] * 256

    for byte in data:
        frequencies[byte] += 1

    length = len(data)
    entropy = 0.0

    for count in frequencies:
        if count:
            probability = count / length

            entropy -= (
                probability *
                math.log2(probability)
            )

    return entropy


def detect_file_type(file_path):
    mime_type, _ = mimetypes.guess_type(
        file_path
    )

    if mime_type:
        return mime_type

    extension = os.path.splitext(
        file_path
    )[1].lower()

    if extension:
        return extension.lstrip(".")

    return "unknown"


def rule_matches_tags(
    rule,
    selected_tags
):
    if not selected_tags:
        return True

    return bool(
        set(rule.tags) &
        set(selected_tags)
    )


def _get_enabled_rules_for_ruleset(
    compiled_rules,
    enabled_rules
):
    """
    Return the enabled rule identifiers that
    exist in this compiled ruleset.

    None means all rules are enabled.
    """

    if enabled_rules is None:
        return None

    identifiers = set()

    for rule in compiled_rules:
        identifiers.add(
            rule.identifier
        )

    return identifiers & enabled_rules


def _extract_string_matches(match):
    """
    Convert yara-python StringMatch objects
    into the flat structure expected by the GUI.

    yara-python 4.5.x stores actual match
    occurrences in StringMatch.instances.
    """

    string_matches = []

    for string_match in match.strings:

        instances = getattr(
            string_match,
            "instances",
            []
        )

        for instance in instances:

            matched_data = getattr(
                instance,
                "matched_data",
                b""
            )

            if isinstance(
                matched_data,
                bytes
            ):
                data = matched_data.hex()

            else:
                data = str(
                    matched_data
                )

            string_matches.append(
                {
                    "identifier": (
                        string_match.identifier
                    ),
                    "offset": getattr(
                        instance,
                        "offset",
                        None
                    ),
                    "length": len(matched_data),
                    "data": data,
                }
            )

    return string_matches


def scan_file(
    file_path,
    rules,
    enabled_rules=None,
    selected_tags=None,
    hash_all=False,
):
    start_time = time.time()

    try:

        file_size = os.path.getsize(
            file_path
        )

        file_type = detect_file_type(
            file_path
        )

        matches = []

        for rule_set in rules:

            compiled = rule_set["compiled"]
            source = rule_set["file"]

            enabled_for_ruleset = (
                _get_enabled_rules_for_ruleset(
                    compiled,
                    enabled_rules
                )
            )

            if (
                enabled_rules is not None
                and not enabled_for_ruleset
            ):
                continue

            yara_matches = compiled.match(
                file_path
            )

            for match in yara_matches:

                if (
                    enabled_rules is not None
                    and match.rule
                    not in enabled_for_ruleset
                ):
                    continue

                if (
                    selected_tags
                    and not rule_matches_tags(
                        match,
                        selected_tags
                    )
                ):
                    continue

                matches.append(
                    {
                        "name": match.rule,
                        "namespace": match.namespace,
                        "tags": list(
                            match.tags
                        ),
                        "meta": dict(
                            match.meta
                        ),
                        "strings": (
                            _extract_string_matches(
                                match
                            )
                        ),
                        "source": source,
                    }
                )

        matched = bool(
            matches
        )

        result = {
            "file": file_path,

            "name": os.path.basename(
                file_path
            ),

            "size": file_size,

            "file_type": file_type,

            "matched": matched,

            "rules": matches,

            "entropy": (
                calculate_entropy(
                    file_path
                )
                if matched
                else None
            ),

            "sha256": (
                calculate_sha256(
                    file_path
                )
                if matched or hash_all
                else None
            ),

            "scan_duration_seconds": (
                time.time() -
                start_time
            ),
        }

        return result

    except Exception as exc:

        try:
            file_size = (
                os.path.getsize(
                    file_path
                )
                if os.path.isfile(
                    file_path
                )
                else 0
            )
        except OSError:
            file_size = 0

        try:
            file_type = detect_file_type(
                file_path
            )
        except Exception:
            file_type = "unknown"

        return {
            "file": file_path,

            "name": os.path.basename(
                file_path
            ),

            "size": file_size,

            "file_type": file_type,

            "matched": False,

            "rules": [],

            "entropy": None,

            "sha256": None,

            "scan_duration_seconds": (
                time.time() -
                start_time
            ),

            "error": str(exc),
        }


def collect_files(
    target_path,
    exclusions=None
):
    exclusions = exclusions or set()

    target_path = os.path.abspath(
        target_path
    )

    normalized_exclusions = {
        os.path.abspath(path)
        for path in exclusions
    }

    if os.path.isfile(
        target_path
    ):

        if (
            target_path
            in normalized_exclusions
        ):
            return []

        return [
            target_path
        ]

    if not os.path.isdir(
        target_path
    ):
        return []

    files = []

    for root, dirs, filenames in os.walk(
        target_path
    ):

        dirs[:] = [
            directory
            for directory in dirs
            if os.path.abspath(
                os.path.join(
                    root,
                    directory
                )
            )
            not in normalized_exclusions
        ]

        for filename in filenames:

            file_path = os.path.abspath(
                os.path.join(
                    root,
                    filename
                )
            )

            if (
                file_path
                in normalized_exclusions
            ):
                continue

            files.append(
                file_path
            )

    return files


def scan_target(
    target_path,
    rules,
    enabled_rules=None,
    selected_tags=None,
    hash_all=False,
    exclusions=None,
    progress_callback=None,
):
    """
    Scan a file or directory.

    Progress callback receives exactly:

        callback(current, total, result)
    """

    files = collect_files(
        target_path,
        exclusions=exclusions
    )

    results = []

    total = len(files)

    for index, file_path in enumerate(
        files,
        start=1
    ):

        result = scan_file(
            file_path,
            rules,
            enabled_rules=enabled_rules,
            selected_tags=selected_tags,
            hash_all=hash_all,
        )

        results.append(
            result
        )

        if progress_callback:

            progress_callback(
                index,
                total,
                result
            )

    matched_count = sum(
        1
        for result in results
        if result.get("matched")
    )

    failed_count = sum(
        1
        for result in results
        if result.get("error")
    )

    rules_triggered = sum(
        len(
            result.get(
                "rules",
                []
            )
        )
        for result in results
    )

    summary = {
        "files_scanned": total,

        "files_matched": matched_count,

        "rules_triggered": rules_triggered,

        "files_failed": failed_count,
    }

    return {
        "results": results,

        "summary": summary,
    }