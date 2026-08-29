import yara
import argparse
import hashlib
import json
import os
import re
import fnmatch
import time
from datetime import datetime, timezone
from colorama import Fore, init


init(autoreset=True)


SCANNER_NAME = "Yara Scanner"
SCANNER_VERSION = "0.1.0"


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()


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


def compile_rules(rule_files, quiet=False):

    rules = []

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

            if not quiet:

                print(
                    f"[+] Loaded rule file: "
                    f"{os.path.relpath(rule_file)}"
                )

        except (
            OSError,
            UnicodeDecodeError,
            yara.Error
        ) as error:

            if not quiet:

                print(
                    Fore.RED
                    + f"[!] Failed to load: "
                    f"{os.path.relpath(rule_file)}"
                )

                print(
                    Fore.RED
                    + f"    Error: {error}"
                )

    if dependencies and not quiet:

        print()

        print(
            f"Included dependencies: "
            f"{len(dependencies)}"
        )

        for dependency in sorted(
            dependencies
        ):

            print(
                f"    └── "
                f"{os.path.relpath(dependency)}"
            )

    return rules


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
    requested_tags=None
):

    scan_start = time.perf_counter()

    try:

        all_matches = []

        for rule_set in rules:

            matches = rule_set["compiled"].match(
                file_path
            )

            for match in matches:

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

        file_size = os.path.getsize(
            file_path
        )

        scan_duration = (
            time.perf_counter()
            - scan_start
        )

        result = {
            "file": file_path,
            "size": file_size,
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

    except (OSError, yara.Error) as error:

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

                    excluded.append(
                        file_path
                    )

                else:

                    files.append(
                        file_path
                    )

    return files, excluded


def print_match(result):

    print()

    print(
        Fore.RED
        + "=" * 50
    )

    print(
        Fore.RED
        + f"[!] MATCH: {result['file']}"
    )

    print(
        Fore.RED
        + f"    Size:   "
        f"{result['size']:,} bytes"
    )

    if result["sha256"]:

        print(
            Fore.RED
            + f"    SHA256: "
            f"{result['sha256']}"
        )

    print(
        Fore.RED
        + f"    Scan time: "
        f"{result['scan_duration_seconds']:.4f} seconds"
    )

    for rule in result["rules"]:

        print(
            Fore.RED
            + f"\n    Rule: "
            f"{rule['name']}"
        )

        print(
            Fore.RED
            + f"    Rule file: "
            f"{rule['source']}"
        )

        if rule["tags"]:

            print(
                Fore.RED
                + f"    Tags: "
                + ", ".join(rule["tags"])
            )

        if rule["meta"]:

            print(
                Fore.RED
                + "    Metadata:"
            )

            for key, value in (
                rule["meta"].items()
            ):

                print(
                    Fore.RED
                    + f"        {key}: {value}"
                )

        for string_match in (
            rule["strings"]
        ):

            print(
                Fore.RED
                + f"        String: "
                f"{string_match['identifier']}"
            )

            print(
                Fore.RED
                + f"        Offset: "
                f"{string_match['offset']:#x}"
            )

            print(
                Fore.RED
                + f"        Data:   "
                f"{string_match['data']!r}"
            )

    print(
        Fore.RED
        + "=" * 50
    )


def print_clean(result, verbose):

    if not verbose:

        print(
            f"[OK] {result['file']}"
        )

        return

    print()

    print("=" * 50)
    print("YARA SCAN")
    print("=" * 50)

    print(
        f"File:   {result['file']}"
    )

    print(
        f"Size:   "
        f"{result['size']:,} bytes"
    )

    if result["sha256"]:

        print(
            f"SHA256: "
            f"{result['sha256']}"
        )

    else:

        print(
            "SHA256: "
            "not calculated"
        )

    print(
        f"Scan time: "
        f"{result['scan_duration_seconds']:.4f} seconds"
    )

    print(
        "\n[-] No matches found."
    )


def print_error(result):

    print(
        Fore.RED
        + f"[!] FAILED: {result['file']}"
    )

    print(
        Fore.RED
        + f"    Error: {result['error']}"
    )

    if "scan_duration_seconds" in result:

        print(
            Fore.RED
            + f"    Scan time: "
            f"{result['scan_duration_seconds']:.4f} seconds"
        )


def create_summary(
    results,
    files_found,
    files_excluded
):

    files_scanned = len(results)

    files_matched = sum(
        1
        for result in results
        if "error" not in result
        and result["matched"]
    )

    rules_triggered = sum(
        len(result["rules"])
        for result in results
        if "error" not in result
    )

    files_failed = sum(
        1
        for result in results
        if "error" in result
    )

    return {
        "files_found": files_found,
        "files_scanned": files_scanned,
        "files_excluded": files_excluded,
        "files_matched": files_matched,
        "rules_triggered": rules_triggered,
        "files_failed": files_failed
    }


def create_rule_statistics(results):

    statistics = {}

    for result in results:

        if "error" in result:
            continue

        for rule in result["rules"]:

            rule_name = rule["name"]

            statistics[rule_name] = (
                statistics.get(
                    rule_name,
                    0
                )
                + 1
            )

    return dict(
        sorted(
            statistics.items(),
            key=lambda item: (
                -item[1],
                item[0].lower()
            )
        )
    )


def make_relative_path(
    path,
    base_directory
):

    return os.path.relpath(
        path,
        base_directory
    )


def prepare_json_results(
    results,
    scanner_directory
):

    prepared = []

    for result in results:

        result_copy = result.copy()

        result_copy["file"] = make_relative_path(
            result_copy["file"],
            scanner_directory
        )

        if "rules" in result_copy:

            result_copy["rules"] = []

            for rule in result["rules"]:

                rule_copy = rule.copy()

                rule_copy["source"] = make_relative_path(
                    rule_copy["source"],
                    scanner_directory
                )

                result_copy["rules"].append(
                    rule_copy
                )

        prepared.append(
            result_copy
        )

    return prepared


def build_json_report(
    results,
    target,
    rules_directory,
    scanner_directory,
    files_found,
    files_excluded,
    started_at,
    duration,
    requested_tags
):

    summary = create_summary(
        results,
        files_found,
        files_excluded
    )

    rule_statistics = create_rule_statistics(
        results
    )

    prepared_results = prepare_json_results(
        results,
        scanner_directory
    )

    return {
        "scanner": {
            "name": SCANNER_NAME,
            "version": SCANNER_VERSION
        },

        "scan": {
            "target": make_relative_path(
                target,
                scanner_directory
            ),

            "rules": make_relative_path(
                rules_directory,
                scanner_directory
            ),

            "tags": requested_tags,

            "started_at": started_at,

            "duration_seconds": round(
                duration,
                4
            )
        },

        "summary": summary,

        "rule_statistics": rule_statistics,

        "results": prepared_results
    }


def output_json(
    report,
    output_file=None
):

    json_data = json.dumps(
        report,
        indent=4,
        ensure_ascii=False
    )

    if output_file:

        try:

            with open(
                output_file,
                "w",
                encoding="utf-8"
            ) as file:

                file.write(
                    json_data
                )

        except OSError as error:

            print(
                Fore.RED
                + f"[!] Failed to write JSON: "
                f"{error}"
            )

            return False

    else:

        print(json_data)

    return True


def print_rule_statistics(results):

    statistics = create_rule_statistics(
        results
    )

    print()
    print("RULE STATISTICS")
    print("-" * 50)

    if not statistics:

        print(
            "No rules triggered."
        )

        return

    max_name_length = max(
        len(name)
        for name in statistics
    )

    for rule_name, count in (
        statistics.items()
    ):

        print(
            f"{rule_name:<{max_name_length}}"
            f"  {count}"
        )


def list_rules(
    rules,
    scanner_directory
):

    rule_count = 0

    print()
    print("=" * 50)
    print("LOADED YARA RULES")
    print("=" * 50)

    for rule_set in rules:

        compiled = rule_set["compiled"]
        source = rule_set["file"]

        for rule in compiled:

            rule_count += 1

            print()
            print(
                f"Rule: {rule.identifier}"
            )

            print(
                f"Source: "
                f"{make_relative_path(
                    source,
                    scanner_directory
                )}"
            )

            if rule.tags:

                print(
                    "Tags:  "
                    + ", ".join(rule.tags)
                )

            else:

                print(
                    "Tags:  none"
                )

            if rule.meta:

                print(
                    "Metadata:"
                )

                for key, value in rule.meta.items():

                    print(
                        f"    {key}: {value}"
                    )

    print()
    print("=" * 50)
    print(
        f"Rules loaded: {rule_count}"
    )
    print("=" * 50)

    return rule_count


def parse_arguments():

    parser = argparse.ArgumentParser(
        description="YARA malware scanning utility"
    )

    parser.add_argument(
        "rules",
        help="Directory containing YARA rules"
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="File or directory to scan"
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed information for clean files"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output scan results as JSON"
    )

    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Write JSON report to FILE"
    )

    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help=(
            "Exclude files or directories matching "
            "PATTERN. Can be used multiple times."
        )
    )

    parser.add_argument(
        "--hash-all",
        action="store_true",
        help="Calculate SHA-256 for every successfully scanned file"
    )

    parser.add_argument(
        "--quiet",
        action="store_true",
        help=(
            "Suppress normal output. "
            "Exit code indicates scan result."
        )
    )

    parser.add_argument(
        "--tag",
        action="append",
        default=[],
        metavar="TAG",
        help=(
            "Only report rules containing TAG. "
            "Can be used multiple times; tags use OR matching."
        )
    )

    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="List loaded YARA rules without scanning"
    )

    return parser.parse_args()


def main():

    args = parse_arguments()

    if args.output and not args.json:

        print(
            Fore.RED
            + "[!] --output requires --json"
        )

        return 1

    scanner_directory = os.path.dirname(
        os.path.abspath(__file__)
    )

    rules_directory = os.path.abspath(
        args.rules
    )

    started_at = datetime.now(
        timezone.utc
    ).isoformat()

    start_time = time.perf_counter()

    if not os.path.isdir(
        rules_directory
    ):

        if not args.quiet:

            print(
                Fore.RED
                + "[!] Rule directory not found: "
                + rules_directory
            )

        return 1

    rule_files = find_rule_files(
        rules_directory
    )

    if not rule_files:

        if not args.quiet:

            print(
                Fore.RED
                + "[!] No YARA rule files found in: "
                + rules_directory
            )

        return 1

    if not args.quiet and not args.json:

        print("=" * 50)
        print("LOADING YARA RULES")
        print("=" * 50)

    rules = compile_rules(
        rule_files,
        quiet=args.quiet or args.json
    )

    if not args.quiet and not args.json:

        print()

        print(
            f"Rule files found:  "
            f"{len(rule_files)}"
        )

        print(
            f"Rule sets loaded:  "
            f"{len(rules)}"
        )

        print("=" * 50)
        print()

    if not rules:

        if not args.quiet:

            print(
                Fore.RED
                + "[!] No rule files could be loaded."
            )

        return 1

    # Rule listing mode
    if args.list_rules:

        if args.json:

            rule_list = []

            for rule_set in rules:

                for rule in rule_set["compiled"]:

                    rule_list.append({
                        "name": rule.identifier,
                        "source": make_relative_path(
                            rule_set["file"],
                            scanner_directory
                        ),
                        "tags": list(rule.tags),
                        "meta": rule.meta
                    })

            report = {
                "scanner": {
                    "name": SCANNER_NAME,
                    "version": SCANNER_VERSION
                },

                "rules": rule_list,

                "summary": {
                    "rules_loaded": len(rule_list)
                }
            }

            if not output_json(
                report,
                args.output
            ):

                return 1

        else:

            list_rules(
                rules,
                scanner_directory
            )

        return 0

    # Scanning requires a target
    if not args.target:

        if not args.quiet:

            print(
                Fore.RED
                + "[!] A target is required unless "
                "--list-rules is used."
            )

        return 1

    target = os.path.abspath(
        args.target
    )

    files, excluded_files = collect_files(
        target,
        args.exclude
    )

    files_found = (
        len(files)
        + len(excluded_files)
    )

    if not files and not excluded_files:

        if not args.quiet:

            print(
                Fore.RED
                + "[!] Target not found: "
                + target
            )

        return 1

    results = []

    for file_path in files:

        results.append(
            scan_file(
                rules,
                file_path,
                hash_all=args.hash_all,
                requested_tags=args.tag
            )
        )

    duration = (
        time.perf_counter()
        - start_time
    )

    summary = create_summary(
        results,
        files_found,
        len(excluded_files)
    )

    if args.json:

        report = build_json_report(
            results,
            target,
            rules_directory,
            scanner_directory,
            files_found,
            len(excluded_files),
            started_at,
            duration,
            args.tag
        )

        success = output_json(
            report,
            args.output
        )

        if not success:
            return 1

        if summary["files_failed"] > 0:
            return 1

        if summary["files_matched"] > 0:
            return 2

        return 0

    if args.quiet:

        if summary["files_failed"] > 0:

            print("ERROR")

            return 1

        if summary["files_matched"] > 0:

            print("MATCH")

            return 2

        print("CLEAN")

        return 0

    if args.exclude:

        print(
            f"Excluded files:   "
            f"{len(excluded_files)}"
        )

        print()

    if args.tag:

        print(
            "Tag filter:       "
            + ", ".join(args.tag)
        )

        print()

    for result in results:

        if "error" in result:

            print_error(result)

        elif result["matched"]:

            print_match(result)

        else:

            print_clean(
                result,
                args.verbose
            )

    print()
    print("=" * 50)
    print("SCAN COMPLETE")
    print("=" * 50)

    print(
        f"Files found:      "
        f"{summary['files_found']}"
    )

    print(
        f"Files scanned:    "
        f"{summary['files_scanned']}"
    )

    print(
        f"Files excluded:   "
        f"{summary['files_excluded']}"
    )

    if summary["files_matched"] > 0:

        print(
            Fore.RED
            + f"Files matched:    "
            f"{summary['files_matched']}"
        )

    else:

        print(
            f"Files matched:    "
            f"{summary['files_matched']}"
        )

    if summary["rules_triggered"] > 0:

        print(
            Fore.RED
            + f"Rules triggered:  "
            f"{summary['rules_triggered']}"
        )

    else:

        print(
            f"Rules triggered:  "
            f"{summary['rules_triggered']}"
        )

    if summary["files_failed"] > 0:

        print(
            Fore.RED
            + f"Files failed:     "
            f"{summary['files_failed']}"
        )

    else:

        print(
            f"Files failed:     "
            f"{summary['files_failed']}"
        )

    print(
        f"Duration:         "
        f"{duration:.4f} seconds"
    )

    print_rule_statistics(
        results
    )

    print("=" * 50)

    if summary["files_failed"] > 0:
        return 1

    if summary["files_matched"] > 0:
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())