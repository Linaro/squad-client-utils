# squad-jobs

Jobs involving [`squad`](https://github.com/Linaro/squad) that are not implemented in [`squad-client`](https://github.com/Linaro/squad-client) or [`squad-report`](https://gitlab.com/Linaro/lkft/reports/squad-report).

## Requirements

To install requirements, from the repo base directory execute:

```
pip install -r requirements.txt
```

## Usage

### `squad-list-changes`: Get all of the changes for a build, compared to a base build.

```
❯ pipenv run ./squad-list-changes -h
usage: squad-list-changes [-h] --group GROUP --project PROJECT --build BUILD --base-build BASE_BUILD

List all changes for a squad build, compared to a base build

optional arguments:
  -h, --help            show this help message and exit
  --group GROUP         squad group
  --project PROJECT     squad project
  --build BUILD         squad build
  --base-build BASE_BUILD
                        squad build to compare to
```

#### Comparing a build to itself should return zero changes

```
❯ pipenv run ./squad-list-changes --group=lkft --project=linux-next-master-sanity --build=next-20211020 --base-build=next-20211020
[]
```

#### Given a collection of changes, get a subset that contains only regressions

```
❯ pipenv run ./squad-list-changes --group=lkft --project=linux-next-master-sanity --build=next-20211020 --base-build=next-20211019 > changes.json

❯ jq '.[] | select(.change=="regression")' changes.json | jq --slurp
```

### `squad-list-results`: Get all of the results for a build

```
❯ pipenv run ./squad-list-results -h
usage: squad-list-results [-h] --group GROUP --project PROJECT --build BUILD

List all results for a squad build

optional arguments:
  -h, --help         show this help message and exit
  --group GROUP      squad group
  --project PROJECT  squad project
  --build BUILD      squad build
```

#### Given a collection of results, get a subset that contains only failures

```
❯ pipenv run ./squad-list-results --group=lkft --project=linux-next-master-sanity --build=next-20211022 > results.json

❯ jq '.[] | select(.status=="fail")' results.json
```

#### `squad-list-failures`: If a build has a lot of tests, filter with the http request instead

```python
filters = {
    "has_known_issues": False,
    "result": False,
}
tests = build.tests(count=ALL, **filters).values()
```

```
❯ pipenv run ./squad-list-failures -h
usage: squad-list-failures [-h] --group GROUP --project PROJECT --build BUILD

List all results for a squad build

optional arguments:
  -h, --help         show this help message and exit
  --group GROUP      squad group
  --project PROJECT  squad project
  --build BUILD      squad build
```

### `squad-list-result-history`: Get all of the results for a test, starting with this build

```
❯ pipenv run ./squad-list-result-history -h
usage: squad-list-result-history [-h] --group GROUP --project PROJECT --build BUILD --environment ENVIRONMENT --suite SUITE --test TEST

List the result history of a test

optional arguments:
  -h, --help            show this help message and exit
  --group GROUP         squad group
  --project PROJECT     squad project
  --build BUILD         squad build
  --environment ENVIRONMENT
                        squad environment
  --suite SUITE         squad suite
  --test TEST           squad test
```

### `squad-list-test`: Get all of the data for a test

```
❯ pipenv run ./squad-list-test --help
usage: squad-list-test [-h] --group GROUP --project PROJECT --build BUILD --environment ENVIRONMENT --suite SUITE --test TEST

List data about a test

optional arguments:
  -h, --help            show this help message and exit
  --group GROUP         squad group
  --project PROJECT     squad project
  --build BUILD         squad build
  --environment ENVIRONMENT
                        squad environment
  --suite SUITE         squad suite
  --test TEST           squad test
```

Given a test, get all of the data about it

```
pipenv run ./squad-list-test --group=lkft --project=linux-next-master --build=next-20211206 --environment=x86_64 --suite=build --test=gcc-10-allnoconfig
```

Example output
```
{
  "url": "https://qa-reports.linaro.org/api/tests/2142352489/",
  "id": 2142352489,
  "name": "build/gcc-10-allnoconfig",
  "short_name": "gcc-10-allnoconfig",
  "status": "pass",
  "result": true,
  "log": null,
  "has_known_issues": false,
  "suite": "build",
  "known_issues": [],
  "build": "next-20211206",
  "environment": "x86_64",
  "group": "lkft",
  "project": "linux-next-master",
  "metadata": {
    "download_url": "https://builds.tuxbuild.com/21uE4xyDMQuUlvCJbZWkSZKVPEL/",
    "git_describe": "next-20211206",
    "git_ref": null,
    "git_repo": "https://gitlab.com/Linaro/lkft/mirrors/next/linux-next",
    "git_sha": "5d02ef4b57f6e7d4dcba14d40cf05373a146a605",
    "git_short_log": "5d02ef4b57f6 (\"Add linux-next specific files for 20211206\")",
    "kconfig": [
      "allnoconfig"
    ],
    "kernel_version": "5.16.0-rc4",
    "git_commit": "5d02ef4b57f6e7d4dcba14d40cf05373a146a605",
    "git_branch": "master",
    "make_kernelversion": "5.16.0-rc4",
    "config": "https://builds.tuxbuild.com/21uE4xyDMQuUlvCJbZWkSZKVPEL/config"
  }
}
```

### `squad-list-metrics`: Get all of the metrics for a build

```
❯ pipenv run ./squad-list-metrics --help
usage: squad-list-metrics [-h] --group GROUP --project PROJECT --build BUILD

List all of the metrics for a squad build

optional arguments:
  -h, --help         show this help message and exit
  --group GROUP      squad group
  --project PROJECT  squad project
  --build BUILD      squad build
```

#### Given a collection of metrics, get a subset that contain build warnings

```
❯ pipenv run ./squad-list-metrics --group=lkft --project=linux-next-master-sanity --build=next-20211118 > results.json

❯ jq '.[] | select(.result>0.0)' results.json | jq --slurp
```

### `squad-create-reproducer`: Get a reproducer for a given group, project, device and suite.

This script gets a recent TuxRun reproducer from SQUAD for a chosen suite. When
a reproducer is found, this is saved to a file and written to stdout.

```
./squad-create-reproducer --help
usage: squad-create-reproducer [-h] --device-name DEVICE_NAME --group GROUP --project
                               PROJECT --suite-name SUITE_NAME [--allow-unfinished]
                               [--build-names BUILD_NAMES [BUILD_NAMES ...]]
                               [--custom-command CUSTOM_COMMAND] [--debug]
                               [--filename FILENAME] [--local]
                               [--search-build-count SEARCH_BUILD_COUNT]

Get the latest TuxRun reproducer for a given group, project, device and suite. The
reproducer will be printed to the terminal and written to a file. Optionally update the
TuxRun reproducer to run custom commands and/or run in the cloud with TuxTest.

options:
  -h, --help            show this help message and exit
  --device-name DEVICE_NAME
                        The device name (for example, qemu-arm64).
  --group GROUP         The name of the SQUAD group.
  --project PROJECT     The name of the SQUAD project.
  --suite-name SUITE_NAME
                        The suite name to grab a reproducer for.
  --allow-unfinished    Allow fetching of reproducers where the build is marked as
                        unfinished.
  --build-names BUILD_NAMES [BUILD_NAMES ...]
                        The list of accepted build names (for example, gcc-12-lkftconfig).
                        Regex is supported.
  --custom-command CUSTOM_COMMAND
                        A custom command to add to the reproducer.
  --debug               Display debug messages.
  --filename FILENAME   Name for the reproducer file, 'reproducer' by default.
  --local               Create a TuxRun reproducer when updating rather than a TuxTest.
  --search-build-count SEARCH_BUILD_COUNT
                        The number of builds to fetch when searching for a reproducer.
```

### `squad-create-reproducer-from-testrun`: Get a reproducer for a given TestRun ID.

This script fetches the build or test reproducer for a given TestRun ID.

```
usage: squad-create-reproducer-from-testrun [-h] --testrun TESTRUN [--debug]
                                            [--filename FILENAME] [--local | --plan]

Provide a SQUAD TestRun ID to download the build or test reproducer for that TestRun. The
reproducer will be printed to the terminal and written to a file.

optional arguments:
  -h, --help           show this help message and exit
  --testrun TESTRUN    The TestRun ID of the build or test to fetch the reproducer for.
  --debug              Display debug messages.
  --filename FILENAME  Name for the reproducer file, 'reproducer' by default.
  --local              Fetch a TuxRun or TuxMake reproducer rather than a TuxSuite reproducer.
  --plan               Fetch a TuxPlan reproducer rather than a TuxTest of TuxBuild reproducer.
```

### `squad-create-skipfile-reproducers`: Creating skipfile reproducers

The `squad-create-skipfile-reproducers` script can be used to create TuxRun or
TuxPlan reproducers for the LTP skipfile.

```
./squad-create-skipfile-reproducers --help
usage: squad-create-skipfile-reproducers [-h] --group GROUP [--allow-unfinished]
                                         [--projects PROJECTS [PROJECTS ...]]
                                         [--build-names BUILD_NAMES [BUILD_NAMES ...]]
                                         [--debug] [--count COUNT]
                                         [--device-names DEVICE_NAMES [DEVICE_NAMES ...]]
                                         [--local] [--project-age PROJECT_AGE]
                                         [--project-regex PROJECT_REGEX]
                                         [--metadata-filename METADATA_FILENAME]
                                         [--skipfile-url SKIPFILE_URL]
                                         [--suite-name SUITE_NAME]

Produce TuxRun or TuxPlan reproducers for the LTP skipfile.

optional arguments:
  -h, --help            show this help message and exit
  --group GROUP         The name of the SQUAD group.
  --allow-unfinished    Allow fetching of reproducers where the build is marked as
                        unfinished.
  --projects PROJECTS [PROJECTS ...]
                        A list of SQUAD projects to be tested.
  --build-names BUILD_NAMES [BUILD_NAMES ...]
                        The list of accepted build names (for example, gcc-12-lkftconfig).
                        Regex is supported.
  --debug               Display debug messages.
  --count COUNT         The number of builds to fetch when searching for a reproducer.
  --device-names DEVICE_NAMES [DEVICE_NAMES ...]
                        The list of device names (for example, qemu-arm64).
  --local               Create a TuxRun reproducer when updating rather than a TuxPlan.
  --project-age PROJECT_AGE
                        Project age in days.
  --project-regex PROJECT_REGEX
                        Regex pattern for project names.
  --metadata-filename METADATA_FILENAME
                        Name for the file containing extra info about the builds.
  --skipfile-url SKIPFILE_URL
                        URL of the skipfile to test.
  --suite-name SUITE_NAME
                        The suite name to grab a reproducer for.
```

### `read-skipfile-results`: Read results from


This script can be used to gather the results from skipfile testing and apply
the relevant updates to the skipfile, optionally pushing these updates to a
test-definitions repo in github

This script has several requirements for running.

Required files:
- a copy of the test-definitions repo to be downloaded in the
  squad-client-utils directory
- a file containing the list of SQUAD builds containing the skipfile results we
  want to read (`--builds-file`, which will look for a file called
  `builds_for_skipfile_runs.txt` by default)
- a metadata csv file containing the reproducer_script_name, run_project,
  device and git describe for each SQUAD build on each line
  (`--metadata-filename`, which will look for a file called `metadata_list.csv`
  by default)

Other requirements:
- If pushing the skipfile updates to Github, you must set up a Github access
  token at `https://github.com/settings/tokens` with access to push commits and
  pull requests to the test-definitions repo.

  This can be achieved by creating a fine-grained personal access token with
  the permissions:
  - Contents: read and write
  - Metadata: read-only
  - Pull requests: read and write


```
usage: read-skipfile-results [-h] --group-name GROUP_NAME --project-name PROJECT_NAME
                             --run-count RUN_COUNT [--builds-file BUILDS_FILE] [--debug]
                             [--github-token GITHUB_TOKEN] [--github-push]
                             [--repo-path REPO_PATH]
                             [--metadata-filename METADATA_FILENAME] [--skipfile SKIPFILE]
                             [--squad-host SQUAD_HOST]

Read results and update skipfile

optional arguments:
  -h, --help            show this help message and exit
  --group-name GROUP_NAME
  --project-name PROJECT_NAME
  --run-count RUN_COUNT
                        The number of runs performed.
  --builds-file BUILDS_FILE
                        File containing the list of SQUAD build names
  --debug               Display debug messages.
  --github-token GITHUB_TOKEN
                        The name of the environment variable containing the Github API
                        token.
  --github-push         Should the results be pushed to Github.
  --repo-path REPO_PATH
                        The path of the test-definitions repo.
  --metadata-filename METADATA_FILENAME
                        Name for the file containing the build info.
  --skipfile SKIPFILE
  --squad-host SQUAD_HOST
```

## Contributing

This (alpha) project is managed on [`github`](https://github.com) at https://github.com/Linaro/squad-client-utils

Open an issue at https://github.com/Linaro/squad-client-utils/issues

Open a pull request at https://github.com/Linaro/squad-client-utils/pulls

For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](https://github.com/Linaro/squad-client-utils/blob/master/LICENSE)
