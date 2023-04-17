#!/usr/bin/python3
# -*- coding: utf-8 -*-
# vim: set ts=4
#
# Copyright 2023-present Linaro Limited
#
# SPDX-License-Identifier: MIT


import logging
import os
import re
from pathlib import Path

import requests
from requests import HTTPError
from squad_client.core.models import ALL, Build, Squad
from squad_client.utils import first, getid

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ReproducerNotFound(Exception):
    """
    Raised when no reproducer can be found.
    """

    def __init__(self, message="No reproducer found"):
        super().__init__(message)


def get_file(path, filename=None):
    """
    Download file if a URL is passed in, then return the filename of the
    downloaded file. If an existing file path is passed in, return the path. If
    a non-existent path is passed in, raise an exception.
    """
    logger.info(f"Getting file from {path}")
    if re.search(r"https?://", path):
        request = requests.get(path, allow_redirects=True)
        request.raise_for_status()
        if not filename:
            filename = path.split("/")[-1]
        else:
            output_file = Path(filename)
            output_file.parent.mkdir(exist_ok=True, parents=True)

        with open(filename, "wb") as f:
            f.write(request.content)
        return filename
    elif os.path.exists(path):
        return path
    else:
        raise Exception(f"Path {path} not found")


def download(
    project, build, build_names, filter_envs=None, filter_suites=None, format_string=None, output_filename=None
):
    """
    From the download_tests squad-client shortcut. Downloads the tests that
    match the filters provided, then searches for a test run where the build
    name matches the accepted build names. The first test run with a matching
    build name will be returned.
    """
    all_envs = project.environments(count=ALL)
    all_suites = project.suites(count=ALL)
    all_testruns = build.testruns(count=ALL, prefetch_metadata=True)

    filters = {
        "count": ALL,
        "fields": "id,name,status,environment,suite,test_run,build,short_name",
    }

    envs = None
    if filter_envs:
        filters["environment__id__in"] = ",".join([str(e.id) for e in filter_envs])
        envs = ",".join([e.slug for e in filter_envs])

    suites = None
    if filter_suites:
        filters["suite__id__in"] = ",".join([str(s.id) for s in filter_suites])
        suites = ",".join([s.slug for s in filter_suites])
        logger.debug(f"Suites: {suites}")
        logger.debug(f"Filters: {filters}")

    filename = output_filename or "result.txt"
    logger.info(
        "Downloading test results for "
        + f'{project.slug}/{build.version}/{envs or "(all envs)"}/{suites or "(all suites)"}'
        + f" to {filename}"
    )

    if format_string is None:
        format_string = "{test.environment.slug}/{test.id}/{test.name} {test.status}"

    tests = build.tests(**filters)
    output = []
    if not tests:
        logger.debug("There are no tests to print")
    testrun = None
    tests_with_build_name = []
    available_build_names = set()
    for test in tests.values():
        if testrun:
            break
        test.build = build
        test.environment = all_envs[getid(test.environment)]
        test.suite = all_suites[getid(test.suite)]
        test.test_run = all_testruns[getid(test.test_run)]
        for build_name in build_names:
            re_match = re.match(f"^{build_name}$", test.test_run.metadata.build_name)
            available_build_names.add(test.test_run.metadata.build_name)
            if re_match:
                logger.info(f"Testrun match {test.test_run.metadata.build_name} {test.test_run.url}")
                logger.debug(f"adding {test.short_name}")
                tests_with_build_name.append(test.test_run)
                output.append(format_string.format(test=test))
                testrun = test.test_run
                break

    with open(filename, "w") as fp:
        for line in output:
            fp.write(line + "\n")

    logger.debug(f"Available build names: {available_build_names}")

    return testrun


def download_tests(project, build, build_names, envs, suites, output_filename=None):
    """
    Wrapper for downloading tests.
    """
    testrun = download(
        project,
        build,
        build_names,
        envs,
        suites,
        "{test.environment.slug}/{test.test_run.metadata.build_name}/{test.test_run.id}/{test.name} {test.status}",
        output_filename,
    )
    return testrun


def find_build(build_names, build_options, suite_names, envs, project):
    """
    Given a list of builds IDs to choose from in a project, find the first one
    that has a match for the build name, suite names and environments
    """
    selected_build = None
    build_name = None
    testrun = None
    suites = None

    # Given a list of builds IDs, find one that contains the suites and that
    # has a matching build name
    for build in build_options.values():
        # only pick builds that are finished
        if not build.finished:
            logger.info(f"Skipping {build.id} as build is not marked finished")
            continue
        logger.info(f"Checking build {build.id}")
        # Create the list of suite IDs from the suite names
        if suite_names:
            suites = []
            for s in suite_names:
                suites += project.suites(slug=s).values()

        # Download the tests for the current build option
        testrun = download_tests(
            project=project,
            build=build,
            build_names=build_names,
            suites=suites,
            envs=envs,
        )
        if not testrun:
            logger.info(f"No tests found that matches the criteria in build ID {build.id}")
            continue
        else:
            break

    if not testrun:
        logger.debug(f"No test for {project.id}-{build.id}-{suites}-{envs}-{build.version}")
    else:
        logger.debug(testrun)
        logger.debug(testrun.metadata)
        logger.debug(testrun.metadata.build_name)
        build_name = testrun.metadata.build_name
        selected_build = testrun.build
    return selected_build, build_name, testrun


def find_reproducer(group, project, device_name, debug, build_names):
    """
    Given a group, project, device and accepted build names, return a
    reproducer for a test run that meets these conditions.
    """
    suite_name = "ltp-syscalls"
    if debug:
        logger.setLevel(level=logging.DEBUG)

    base_group = Squad().group(group)
    if base_group is None:
        logger.error(f"Get group failed. Group not found: '{group}'.")
        raise ReproducerNotFound

    base_project = base_group.project(project)
    if base_project is None:
        logger.error(f"Get project failed. project not found: '{project}'.")
        raise ReproducerNotFound

    logger.debug(f"build name {build_names}")

    metadata = first(Squad().suitemetadata(suite=suite_name, kind="test"))

    if metadata is None:
        logger.error(f'There is no suite named "{suite_name}"')
        raise ReproducerNotFound

    # == get a build that contains a run of ltp-syscalls ==

    # Get the latest 10 builds in the project so we don't pick something old
    build_options = base_project.builds(count=10, ordering="-id")
    build = None
    environment = base_project.environment(device_name)
    build_name = None

    logger.debug("Find build")
    build, build_name, testrun = find_build(build_names, build_options, [suite_name], [environment], base_project)
    try:
        build = Build(getid(testrun.build))
        build_name = testrun.metadata.build_name
    except AttributeError as e:
        logger.error(f"{e}. Check testrun exists for this project, suite name and build name combination.")
        raise ReproducerNotFound

    if not build or not build_name or not testrun:
        logger.error(f"No build found. Build: {build} build_name: {build_name} testrun: {testrun}")
        logger.error(f"No build found for project: {project} device: {device_name}")
        raise ReproducerNotFound
    else:
        logger.info(f"Build {build}")
        logger.info(f"Found build {build.url}")

        # In theory there should only be one of those
        logger.debug(f"Testrun id {testrun.id}")
        download_url = testrun.metadata.download_url
        if download_url is None:
            if testrun.metadata.config is None:
                logger.info("There is no way to determine download_url")
                raise ReproducerNotFound
            download_url = testrun.metadata.config.replace("config", "")

    try:
        tuxrun = get_file(f"{testrun.job_url}/reproducer")
    except HTTPError:
        logger.error(f"Reproducer not found at {testrun.job_url}!")
        raise ReproducerNotFound
    return tuxrun
