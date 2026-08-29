import fnmatch
import hashlib
import math
import os
import time


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()


def calculate_entropy(file_path):
    """
    Calculate Shannon entropy for the entire file.

    Returns a value between 0.0 and 8.0.
    """

    counts = [0] * 256
    total = 0

    with open(file_path, "rb") as file:

        while chunk := file.read(1024 * 1024):

            total += len(chunk)

            for byte in chunk:
                counts[byte] += 1

    if total == 0:
        return 0.0

    entropy = 0.0

    for count in counts:

        if count == 0:
            continue

        probability = count / total

        entropy -= (
            probability
            * math.log2(probability)
        )

    return round(entropy, 4)


def detect_file_type(file_path):
    """
    Basic content-based file type detection.

    This intentionally avoids external dependencies.
    """

    try:

        with open(file_path, "rb") as file:
            header = file.read(16)

        # Windows PE
        if header.startswith(b"MZ"):
            return "Windows PE executable"

        # ELF
        if header.startswith(b"\x7fELF"):
            return "ELF executable"

        # PDF
        if header.startswith(b"%PDF"):
            return "PDF document"

        # ZIP
        if header.startswith(b"PK\x03\x04"):
            return "ZIP archive"

        # GZIP
        if header.startswith(b"\x1f\x8b"):
            return "GZIP compressed data"

        # PNG
        if header.startswith(
            b"\x89PNG\r\n\x1a\n"
        ):
            return "PNG image"

        # JPEG
        if header.startswith(b"\xff\xd8\xff"):
            return "JPEG image"

        # GIF
        if header.startswith(b"GIF87a"):
            return "GIF image"

        if header.startswith(b"GIF89a"):
            return "GIF image"

        # RAR
        if header.startswith(b"Rar!\x1a\x07"):
            return "RAR archive"

        # 7-Zip
        if header.startswith(
            b"7z\xbc\xaf'\x1c"
        ):
            return "7-Zip archive"

        # Windows shortcut
        if (
            len(header) >= 4
            and header[:4] == b"\x4c\x00\x00\x00"
        ):
            return "Windows shortcut"

        # Otherwise use extension
        extension = os.path.splitext(
            file_path
        )[1].lower()

        extension_types = {
            ".txt": "Text file",
            ".log": "Log file",
            ".json": "JSON document",
            ".xml": "XML document",
            ".html": "HTML document",
            ".htm": "HTML document",
            ".py": "Python source",
            ".js": "JavaScript source",
            ".ps1": "PowerShell script",
            ".bat": "Batch script",
            ".cmd": "Windows command script",
            ".dll": "Windows DLL",
            ".sys": "Windows system file",
            ".doc": "Microsoft Word document",
            ".docx": "Microsoft Word document",
            ".xls": "Microsoft Excel document",
            ".xlsx": "Microsoft Excel document",
            ".ppt": "Microsoft PowerPoint document",
            ".pptx": "Microsoft PowerPoint document",
            ".zip": "ZIP archive",
            ".rar": "RAR archive",
            ".7z": "7-Zip archive",
        }

        return extension_types.get(
            extension,
            "Unknown"
        )

    except Exception:
        return "Unknown"


def rule_matches_tags(match, requested_tags):

    if not requested_tags:
        return True

    rule_tags = {
        tag.lower()
        for tag in match.tags
    }

    requested_tags = {
        tag.lower()
        for tag in requested_tags
    }

    return bool(
        rule_tags & requested_tags
    )


def scan_file(
    rules,
    file_path,
    hash_all=False,
    requested_tags=None,
    enabled_rules=None
):

    scan_start = time.perf_counter()

    try:

        file_size = os.path.getsize(
            file_path
        )

        file_type = detect_file_type(
            file_path
        )

        entropy = calculate_entropy(
            file_path
        )

        all_matches = []

        for rule_set in rules:

            matches = rule_set["compiled"].match(
                file_path
            )

            for match in matches:

                # ------------------------------------------
                # Enabled rule filtering
                # ------------------------------------------

                if (
                    enabled_rules is not None
                    and match.rule not in enabled_rules
                ):
                    continue

                if not rule_matches_tags(
                    match,
                    requested_tags
                ):
                    continue

                all_matches.append({
                    "match": match,
                    "source": rule_set["file"]
                })

        matched = len(all_matches) > 0

        file_hash = None

        if matched or hash_all:

            file_hash = calculate_sha256(
                file_path
            )

        scan_duration = (
            time.perf_counter()
            - scan_start
        )

        result = {
            "file": file_path,
            "size": file_size,
            "file_type": file_type,
            "entropy": entropy,
            "sha256": file_hash,
            "matched": matched,
            "scan_duration_seconds": round(
                scan_duration,
                4
            ),
            "rules": []
        }

        for match_data in all_matches:

            match = match_data["match"]
            source = match_data["source"]

            rule_data = {
                "name": match.rule,
                "source": source,
                "tags": list(match.tags),
                "meta": match.meta,
                "strings": []
            }

            for string_match in match.strings:

                for instance in string_match.instances:

                    rule_data["strings"].append({
                        "identifier":
                            string_match.identifier,

                        "offset":
                            instance.offset,

                        "data":
                            instance.matched_data.decode(
                                "utf-8",
                                errors="replace"
                            )
                    })

            result["rules"].append(
                rule_data
            )

        return result

    except Exception as error:

        scan_duration = (
            time.perf_counter()
            - scan_start
        )

        return {
            "file": file_path,
            "error": str(error),
            "scan_duration_seconds": round(
                scan_duration,
                4
            )
        }


def collect_files(
    target,
    exclude_patterns=None
):

    files = []
    excluded = []

    if exclude_patterns is None:
        exclude_patterns = []

    def should_exclude(path):

        normalized_path = os.path.normpath(
            path
        )

        filename = os.path.basename(
            path
        )

        for pattern in exclude_patterns:

            if fnmatch.fnmatch(
                filename,
                pattern
            ):
                return True

            if fnmatch.fnmatch(
                normalized_path,
                pattern
            ):
                return True

            path_parts = normalized_path.split(
                os.sep
            )

            if any(
                fnmatch.fnmatch(
                    part,
                    pattern
                )
                for part in path_parts
            ):
                return True

        return False

    if os.path.isfile(target):

        if should_exclude(target):
            excluded.append(target)
        else:
            files.append(target)

    elif os.path.isdir(target):

        for root, dirs, filenames in os.walk(target):

            dirs[:] = [
                directory
                for directory in dirs
                if not should_exclude(
                    os.path.join(
                        root,
                        directory
                    )
                )
            ]

            for filename in filenames:

                file_path = os.path.join(
                    root,
                    filename
                )

                if should_exclude(file_path):
                    excluded.append(file_path)
                else:
                    files.append(file_path)

    return files, excluded


def scan_target(
    rules,
    target,
    hash_all=False,
    requested_tags=None,
    exclude_patterns=None,
    enabled_rules=None,
    progress_callback=None
):

    files, excluded_files = collect_files(
        target,
        exclude_patterns
    )

    results = []

    total_files = len(files)

    if progress_callback:

        progress_callback(
            0,
            total_files,
            None
        )

    for index, file_path in enumerate(
        files,
        start=1
    ):

        result = scan_file(
            rules,
            file_path,
            hash_all=hash_all,
            requested_tags=requested_tags,
            enabled_rules=enabled_rules
        )

        results.append(result)

        if progress_callback:

            progress_callback(
                index,
                total_files,
                result
            )

    summary = {
        "files_found":
            len(files) + len(excluded_files),

        "files_scanned":
            len(results),

        "files_excluded":
            len(excluded_files),

        "files_matched":
            sum(
                1
                for result in results
                if "error" not in result
                and result["matched"]
            ),

        "rules_triggered":
            sum(
                len(result["rules"])
                for result in results
                if "error" not in result
            ),

        "files_failed":
            sum(
                1
                for result in results
                if "error" in result
            )
    }

    return {
        "results": results,
        "summary": summary,
        "excluded_files": excluded_files
    }
