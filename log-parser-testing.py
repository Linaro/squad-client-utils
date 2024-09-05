#!/usr/bin/env python3

import argparse
import hashlib
import logging
import re
from collections import defaultdict
from pathlib import Path

from squad_client.core.api import SquadApi
from squad_client.core.models import TestRun
from tuxrun.utils import slugify

from squadutilslib import get_file

SquadApi.configure(cache=3600, url="https://qa-reports.linaro.org/")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

REGEX_NAME = 0
REGEX_BODY = 1
REGEX_EXTRACTED_NAME = 2

MULTILINERS = [
    (
        "check-kernel-exception",
        r"-+\[? cut here \]?-+.*?-+\[? end trace \w* \]?-+",
        r"\d][^\+\n]*",
    ),
    (
        "check-kernel-kasan",
        r"=+\n\[[\s\.\d]+\]\s+BUG: KASAN:.*?=+",
        r"BUG: KASAN:[^\+\n]*",
    ),
    (
        "check-kernel-kfence",
        r"=+\n\[[\s\.\d]+\]\s+BUG: KFENCE:.*?=+",
        r"BUG: KFENCE:[^\+\n]*",
    ),
]

ONELINERS = [
    (
        "check-kernel-oops",
        r"^[^\n]+Oops(?: -|:).*?$",
        r"Oops[^\+\n]*",
    ),
    (
        "check-kernel-fault",
        r"^[^\n]+Unhandled fault.*?$",
        r"Unhandled [^\+\n]*",
    ),
    (
        "check-kernel-warning",
        r"^[^\n]+WARNING:.*?$",
        r"WARNING: [^\+\n]*",
    ),
    (
        "check-kernel-bug",
        r"^[^\n]+(?: kernel BUG at|BUG:).*?$",
        r"BUG: [^\+\n]*",
    ),
    (
        "check-kernel-invalid-opcode",
        r"^[^\n]+invalid opcode:.*?$",
        r"invalid opcode: [^\+\n]*",
    ),
    (
        "check-kernel-panic",
        r"Kernel panic - not syncing.*?$",
        r"Kernel [^\+\n]*",
    ),
]

# Tip: broader regexes should come first
REGEXES = MULTILINERS + ONELINERS


def arg_parser():
    parser = argparse.ArgumentParser(description="Test out SQUAD log parser patterns")

    parser.add_argument(
        "--file",
        help="Path to a single log file to test",
    )

    parser.add_argument(
        "--directory",
        help="Path to a directory containing one or more log files named `full_log.log`. Log parser outputs will be places in a directory next to each full log.",
    )

    parser.add_argument(
        "--testrun",
        help="SQUAD TestRun ID for a single TestRun log to test. This will download the file to `./<testrun>.log` then run the log parser",
    )

    return parser


class LogParserLib:
    """
    This should later be moved to a common library that both SQUAD and the log
    parser testing script can use.
    """

    @classmethod
    def __compile_regexes(self, regexes):
        combined = [r"(%s)" % r[REGEX_BODY] for r in regexes]
        return re.compile(r"|".join(combined), re.S | re.M)

    @classmethod
    def __join_matches(self, matches, regexes):
        """
        group regex in python are returned as a list of tuples which each
        group match in one of the positions in the tuple. Example:
        regex = r'(a)|(b)|(c)'
        matches = [
            ('match a', '', ''),
            ('', 'match b', ''),
            ('match a', '', ''),
            ('', '', 'match c')
        ]
        """
        snippets = {regex_id: [] for regex_id in range(len(regexes))}
        for match in matches:
            for regex_id in range(len(regexes)):
                if len(match[regex_id]) > 0:
                    snippets[regex_id].append(match[regex_id])
        return snippets

    @classmethod
    def __create_shasum(self, snippet):
        sha = hashlib.sha256()
        without_numbers = re.sub(r"(0x[a-f0-9]+|[<\[][0-9a-f]+?[>\]]|\d+)", "", snippet)
        without_time = re.sub(r"^\[[^\]]+\]", "", without_numbers)
        sha.update(without_time.encode())
        return sha.hexdigest()

    @classmethod
    def __create_name(self, snippet, regex):
        matches = regex.findall(snippet)
        if not matches:
            return None
        snippet = matches[0]
        without_numbers = re.sub(r"(0x[a-f0-9]+|[<\[][0-9a-f]+?[>\]]|\d+)", "", snippet)
        without_time = re.sub(r"^\[[^\]]+\]", "", without_numbers)
        # Truncate the name so it is max 190 characters - this ensures the name
        # + "-<sha>" will not be long than 255 characters
        return slugify(without_time)[:190]

    @classmethod
    def __group_snippets_by_name(self, lines, test_name, test_name_regex):
        """
        There will be at least one test per regex. If there were any match for a given
        regex, then a new test will be generated using test_name + shasum. This helps
        comparing kernel logs across different builds
        """
        snippets_by_regex_name = dict()
        snippets_by_generated_test_name_and_sha = dict()

        snippets_by_regex_name[test_name] = "\n".join(lines)

        # Some lines of the matched regex might be the same, and we don't want
        # to create multiple tests like test1-sha1, test1-sha1, etc, so we'll
        # create a set of sha1sums then create only new tests for unique sha's
        shas = defaultdict(set)
        for line in lines:
            name_and_sha = ""
            if test_name_regex:
                name = self.__create_name(line, test_name_regex)
                if name:
                    name_and_sha = name + "-"
            name_and_sha += self.__create_shasum(line)
            shas[name_and_sha].add(line)

        for sha, lines in shas.items():
            name = f"{test_name}-{sha}"
            snippets_by_generated_test_name_and_sha[name] = "\n---\n".join(lines)

        return snippets_by_regex_name, snippets_by_generated_test_name_and_sha

    @classmethod
    def parse_log(self, log, regexes):
        regex = self.__compile_regexes(regexes)
        matches = regex.findall(log)
        snippets = self.__join_matches(matches, regexes)

        snippets_by_regex_name = dict()
        snippets_by_generated_test_name_and_sha = dict()

        for regex_id in range(len(regexes)):
            test_name = REGEXES[regex_id][REGEX_NAME]
            test_name_regex = None
            if REGEXES[regex_id][REGEX_EXTRACTED_NAME] is not None:
                test_name_regex = re.compile(
                    REGEXES[regex_id][REGEX_EXTRACTED_NAME], re.S | re.M
                )
            (
                snippets_by_regex_name[regex_id],
                snippets_by_generated_test_name_and_sha[regex_id],
            ) = self.__group_snippets_by_name(
                snippets[regex_id], test_name, test_name_regex
            )

        return snippets_by_regex_name, snippets_by_generated_test_name_and_sha


class LogParserUtilities:
    @classmethod
    def cutoff_boot_log(self, log):
        # Attempt to split the log in " login:"
        logs = log.split(" login:", 1)

        # 1 string means no split was done, consider all logs as test log
        if len(logs) == 1:
            return "", log

        boot_log = logs[0]
        test_log = logs[1]
        return boot_log, test_log

    @classmethod
    def kernel_msgs_only(self, log):
        kernel_msgs = re.findall(r"(\[[ \d]+\.[ \d]+\] .*?)$", log, re.S | re.M)
        return "\n".join(kernel_msgs)


class LogParserTester:

    @classmethod
    def post_process_log(self, log):
        boot_log, test_log = LogParserUtilities.cutoff_boot_log(log)
        logs = {
            "boot": boot_log,
            "test": test_log,
        }

        for log_type, log in logs.items():
            log = LogParserUtilities.kernel_msgs_only(log)
            suite_slug = f"log-parser-{log_type}"
            logger.info(f"suite slug: {suite_slug}")
            snippets_by_regex_name, snippets_by_generated_test_name_and_sha = (
                LogParserLib.parse_log(log, REGEXES)
            )

        return snippets_by_generated_test_name_and_sha, snippets_by_regex_name


if __name__ == "__main__":
    args = arg_parser().parse_args()
    if args.testrun:
        file = get_file(TestRun(args.testrun).log_file, f"{args.testrun}.log")
        log = Path(file).read_text()
        LogParserTester.post_process_log(log)
    if args.file:
        if Path(args.file).is_file():
            log = Path(args.file).read_text()
            LogParserTester.post_process_log(log)
        else:
            logger.error(f"{args.file} is not a file.")
    if args.directory:
        log_dir_by_regex_name = "logs_regex_name"
        log_dir_by_generated_test_name_and_sha = "logs_generated_test_name_and_sha"
        if Path(args.directory).is_dir():
            logs = list(Path(args.directory).rglob("full_log.log"))
            for log_file_path in logs:
                log = Path(log_file_path).read_text()
                snippets_by_generated_test_name_and_sha, snippets_by_regex_name = (
                    LogParserTester.post_process_log(log)
                )
                for (
                    snippet_id,
                    snippets,
                ) in snippets_by_generated_test_name_and_sha.items():
                    for test_name, log_lines in snippets.items():
                        extracted_logs_path = (
                            log_file_path.parent
                            / Path(log_dir_by_generated_test_name_and_sha)
                            / Path(test_name)
                        )
                        extracted_logs_path.parent.mkdir(parents=True, exist_ok=True)
                        extracted_logs_path.write_text(log_lines)
                        logger.info(extracted_logs_path)
                for (
                    snippet_id,
                    snippets,
                ) in snippets_by_regex_name.items():
                    for test_name, log_lines in snippets.items():
                        extracted_logs_path = (
                            log_file_path.parent
                            / Path(log_dir_by_regex_name)
                            / Path(test_name)
                        )
                        extracted_logs_path.parent.mkdir(parents=True, exist_ok=True)
                        extracted_logs_path.write_text(log_lines)
                        logger.info(extracted_logs_path)
        else:
            logger.error(f"{args.file} is not a directory.")
