#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim: set ts=4
#
# Copyright 2023-present Linaro Limited
#
# SPDX-License-Identifier: MIT


from logging import DEBUG, INFO, basicConfig, getLogger
from os import path, remove
from pathlib import Path
from re import findall, match, search, sub
from time import sleep

from requests import HTTPError, get
from squad_client.core.models import Build, Squad, TestRun
from squad_client.shortcuts import download_tests
from squad_client.utils import first, getid
from tuxrun.utils import slugify
from yaml import FullLoader, dump, load

basicConfig(level=INFO)
logger = getLogger(__name__)


class ReproducerNotFound(Exception):
    """
    Raised when no reproducer can be found.
    """

    def __init__(self, message="No reproducer found"):
        super().__init__(message)


def get_file(path, filename=None, headers=None):
    """
    Download file if a URL is passed in, then return the filename of the
    downloaded file. If an existing file path is passed in, return the path. If
    a non-existent path is passed in, raise an exception.
    """
    logger.debug(f"Getting file from {path}")
    if search(r"https?://", path):
        request = get(path, allow_redirects=True, headers=headers)
        request.raise_for_status()
        if not filename:
            filename = path.split("/")[-1]
        else:
            output_file = Path(filename)
            output_file.parent.mkdir(exist_ok=True, parents=True)

        with open(filename, "wb") as f:
            f.write(request.content)
        return filename
    elif path.exists(path):
        return path
    else:
        raise Exception(f"Path {path} not found")


def get_reproducer_from_testrun(testrun_id, filename, local=False):
    """Given a testrun, download its reproducer."""
    testrun = TestRun(testrun_id)
    reproducer = None

    # If there is a download_url try to treat it as a build
    if testrun.metadata.download_url:
        try:
            download_file = testrun.metadata.download_url + "/tux_plan.yaml"
            if local:
                download_file = testrun.metadata.download_url + "/tuxmake_reproducer.sh"
            reproducer_file = get_file(download_file, filename)
            with open(reproducer_file) as f:
                reproducer = f.read()
        except HTTPError:
            pass

    if not reproducer:
        # If no build reproducer was found, treat it as a test
        try:
            download_file = testrun.metadata.job_url + "/tux_plan"
            if local:
                download_file = testrun.metadata.job_url + "/reproducer"
            reproducer_file = get_file(download_file, filename)
            with open(reproducer_file) as f:
                reproducer = f.read()
        except HTTPError:
            logger.error("No build or test reproducer found.")
            raise ReproducerNotFound

    return reproducer


def filter_projects(projects, pattern):
    filtered = []
    for p in projects:
        if match(pattern, p.slug):
            filtered.append(p)
    return filtered


def get_projects(group, pattern, modtime):
    projects = Squad().projects(group__slug=group, datetime__gte=modtime, count=-1)
    filtered_projects = []
    for p in filter_projects(projects.values(), pattern):
        filtered_projects.append(p.slug)
    return filtered_projects


def find_first_good_testrun(
    build_names,
    builds,
    suite_names,
    envs,
    project,
    allow_unfinished=False,
    output_filename="result.txt",
):
    """
    Given a list of builds IDs to choose from in a project, find the first one
    that has a match for the build name, suite names and environments
    """

    # Given a list of builds IDs, find one that contains the suites and that
    # has a matching build name
    for build in builds.values():
        suites = []
        # Only pick builds that are finished, unless we specify that unfinished
        # builds are allowed
        if not build.finished and not allow_unfinished:
            logger.debug(f"Skipping {build.id} as build is not marked finished")
            continue
        logger.debug(f"Checking build {build.id}")
        # Create the list of suite IDs from the suite names
        if suite_names:
            for s in suite_names:
                suites += project.suites(slug=s).values()

        if path.exists(output_filename):
            remove(output_filename)

        # Use download_tests to gather filtered test results (build_name does not
        # currently work as a filter)
        download_tests(
            project,
            build,
            envs,
            suites,
            "{test.test_run.metadata.build_name}/{test.test_run.id}",
            output_filename,
        )

        # Look in the file that contains the downloaded tests and see if there is a
        # match for one of the desired build_names
        file_open = open(output_filename, "r")
        file_lines = file_open.readlines()

        for line in file_lines:
            build_name, run_id = line.split("/")
            for allowed_build_name in build_names:
                re_match = match(f"^{allowed_build_name}$", build_name)
                if re_match:
                    # Return a TestRun with a matching build name, project, environment, suite
                    # if it exists
                    return TestRun(run_id)

    # If no matching testrun found
    return None


def get_reproducer(
    group,
    project,
    device_name,
    debug,
    build_names,
    suite_name,
    count,
    filename,
    allow_unfinished=False,
    local=False,
):
    """
    Given a group, project, device and accepted build names, return a
    reproducer for a test run that meets these conditions.
    """
    if debug:
        logger.setLevel(level=DEBUG)

    base_group = Squad().group(group)
    if base_group is None:
        logger.error(f"Get group failed. Group not found: {group}")
        raise ReproducerNotFound

    base_project = base_group.project(project)
    if base_project is None:
        logger.error(f"Get project failed. project not found: {project}")
        raise ReproducerNotFound

    logger.debug(f"build name {build_names}")

    metadata = first(Squad().suitemetadata(suite=suite_name, kind="test"))

    if metadata is None:
        logger.error(f"There is no suite named: {suite_name}")
        raise ReproducerNotFound

    # == get a build that contains a run of the specified suite ==

    # Get the latest N builds in the project so we don't pick something old
    builds = base_project.builds(count=count, ordering="-id")
    environment = base_project.environment(device_name)

    logger.debug("Find build")

    testrun = find_first_good_testrun(
        build_names, builds, [suite_name], [environment], base_project, allow_unfinished
    )

    # Get the reproducer if a testrun is found
    if testrun:
        logger.debug(
            f"Found testrun {testrun} with build_name {testrun.metadata.build_name}, url: {testrun.url}, git_desc: {Build(getid(testrun.build)).metadata.git_describe}"
        )

        # In theory there should only be one of those
        logger.debug(f"Testrun id: {testrun.id}")

        reproducer = get_reproducer_from_testrun(
            testrun_id=testrun.id, filename=filename, plan=False, local=local
        )
        return (
            reproducer,
            Build(getid(testrun.build)).metadata.git_describe,
            testrun.metadata.build_name,
        )
    else:
        raise ReproducerNotFound


def generate_command_name_from_list(name_list):
    """
    If there is a list of tests to run, this function will sort these tests
    alphabetically, turn the list into a string and then remove any characters
    non-alphanumeric characters that would be dropped from the test name.
    """
    sorted_list = sorted(name_list)

    command_name = slugify("-".join(sorted_list))

    return command_name


def create_custom_reproducer(
    reproducer, suite, custom_commands, filename, local=False, command_name=None
):
    """
    Given an existing TuxRun or TuxTest reproducer, edit this reproducer to run
    a given custom command.
    """
    build_cmdline = ""

    if not command_name:
        command_name = custom_commands

    for line in reproducer.split("\n"):
        if ("tuxsuite test submit" in line and not local) or (
            "tuxrun --runtime" in line and local
        ):
            line = sub(r"--tests \S+ ", "", line)
            line = sub(r"--parameters SHARD_INDEX=\S+ ", "", line)
            line = sub(r"--parameters SHARD_NUMBER=\S+ ", "", line)
            line = sub(r"--parameters SKIPFILE=\S+ ", "", line)
            line = sub(f"{suite}=\\S+", "commands=5", line)
            if local:
                build_cmdline = path.join(
                    build_cmdline + line.strip() + ' --save-outputs --log-file -"'
                ).strip()
                build_cmdline = build_cmdline.replace('-"', f"- -- '{custom_commands}'")
            else:
                build_cmdline = path.join(
                    build_cmdline
                    + line.strip()
                    + f''' --parameters command-name={command_name} --commands "'{custom_commands}'"'''
                ).strip()

    reproducer_list = f"""#!/bin/bash\n{build_cmdline}"""
    Path(filename).write_text(reproducer_list, encoding="utf-8")

    return Path(filename).read_text(encoding="utf-8")


def create_ltp_custom_command(tests):
    return f"cd /opt/ltp && ./runltp -s {' '.join(tests)}"


def tuxtest_to_tuxplan_entry(tuxsuite_test):
    tuxsuite_test = sub("tuxsuite test submit", "", tuxsuite_test)
    split_params = tuxsuite_test.split(" --")

    dict_entry = dict()
    for item in split_params:
        params_list = findall(r"""(\S+) (.+)""", item)
        for params in params_list:
            key, value = params
            # Change dashes '-' to underscores '_' in key as TuxPlans use underscores in
            # parameter names rather than dashes.
            key = sub(r"-", r"_", key)
            if key == "timeouts":
                test, timeout = value.split("=")
                if key in dict_entry:
                    dict_entry[key][test] = int(timeout)
                else:
                    dict_entry[key] = dict()
                    dict_entry[key][test] = int(timeout)
            elif key == "parameters" and "=" in value:
                sub_key, sub_val = value.split("=")
                if key in dict_entry:
                    dict_entry[key][sub_key] = sub_val
                else:
                    dict_entry[key] = dict()
                    dict_entry[key][sub_key] = sub_val
            elif key in dict_entry:
                if not isinstance(dict_entry[key], list):
                    dict_entry[key] = [dict_entry[key]]
                dict_entry[key].append(value)
            elif key == "commands":
                value = sub(r"""['"]+""", r"", value)
                dict_entry[key] = [value]
            elif key == "overlay":
                dict_entry[key] = [value]
            else:
                dict_entry[key] = value

    return dict_entry


def create_tuxsuite_plan_from_tuxsuite_tests(tuxtest_filename, plan_name):
    tuxtest_list = open(tuxtest_filename).read().splitlines()
    tuxplan_entries = []
    for tuxtest in tuxtest_list:
        # Check the line contains a tuxsuite test command
        if "tuxsuite test" in tuxtest:
            entry = tuxtest_to_tuxplan_entry(tuxtest)
            tuxplan_entries.append(entry)

    test_yaml_str = f"""
version: 1
name: {plan_name}
description: Run tests from customised reproducers.
jobs:
- name: test-command
"""
    plan = load(test_yaml_str, Loader=FullLoader)
    plan["jobs"][0]["tests"] = tuxplan_entries

    plan_txt = dump(plan, sort_keys=False, default_flow_style=False)

    with open(plan_name, "w") as f:
        f.write(plan_txt)
        f.close()
        print(f"plan file updated: {plan_name}")

    return plan_txt


def wait_for_builds(project, squad_build_list):
    squad_build_list_copy = squad_build_list[:]
    index = 0
    while squad_build_list_copy:
        # Fetch build data by name
        build_name = squad_build_list_copy[index]
        build = first(project.builds(version=build_name))

        # See if build finished
        if build.finished:
            squad_build_list_copy.remove(build_name)
            if not squad_build_list_copy:
                return 0
        else:
            index += 1
            # If we are still waiting for things to finish, sleep so we don't
            # spam the SQUAD server
            sleep(10)
        index = index % len(squad_build_list_copy)
