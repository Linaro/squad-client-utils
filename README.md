# squad-jobs

Jobs involving [`squad`](https://github.com/Linaro/squad) that are not implemented in [`squad-client`](https://github.com/Linaro/squad-client) or [`squad-report`](https://gitlab.com/Linaro/lkft/reports/squad-report).

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

### `get-kconfig`: Get all of the kernel configs for a build test

```
❯ pipenv run ./get-kconfig --help
usage: get-kconfig [-h] --tuxconfig TUXCONFIG --name NAME

List all kernel configs for a build test

optional arguments:
  -h, --help            show this help message and exit
  --tuxconfig TUXCONFIG
                        tuxconfig yaml
  --name NAME           test name
```

- Note: More than one result may be returned. Multiple architectures can use the same toolchain and kernel configs.
- Note: Make variables are not used to generate the hash.

```
❯ pipenv run ./get-kconfig --tuxconfig=tuxconfig.yml --name=clang-12-defconfig-b9979cfa
```

```
[
  {
    "name": "clang-12-defconfig-b9979cfa",
    "set": "i386-clang-12",
    "build": {
      "target_arch": "i386",
      "toolchain": "clang-12",
      "kconfig": [
        "defconfig",
        "https://raw.githubusercontent.com/Linaro/meta-lkft/sumo/recipes-kernel/linux/files/lkft.config",
        "https://raw.githubusercontent.com/Linaro/meta-lkft/sumo/recipes-kernel/linux/files/lkft-crypto.config",
        "https://raw.githubusercontent.com/Linaro/meta-lkft/sumo/recipes-kernel/linux/files/distro-overrides.config",
        "https://raw.githubusercontent.com/Linaro/meta-lkft/sumo/recipes-kernel/linux/files/systemd.config",
        "https://raw.githubusercontent.com/Linaro/meta-lkft/sumo/recipes-kernel/linux/files/virtio.config",
        "CONFIG_IGB=y",
        "CONFIG_UNWINDER_FRAME_POINTER=y"
      ]
    }
  },
  {
    "name": "clang-12-defconfig-b9979cfa",
    "set": "x86-clang-12",
    "build": {
      "target_arch": "x86_64",
      "toolchain": "clang-12",
      "make_variables": {
        "LLVM_IAS": 0
      },
      "kconfig": [
        "defconfig",
        "https://raw.githubusercontent.com/Linaro/meta-lkft/sumo/recipes-kernel/linux/files/lkft.config",
        "https://raw.githubusercontent.com/Linaro/meta-lkft/sumo/recipes-kernel/linux/files/lkft-crypto.config",
        "https://raw.githubusercontent.com/Linaro/meta-lkft/sumo/recipes-kernel/linux/files/distro-overrides.config",
        "https://raw.githubusercontent.com/Linaro/meta-lkft/sumo/recipes-kernel/linux/files/systemd.config",
        "https://raw.githubusercontent.com/Linaro/meta-lkft/sumo/recipes-kernel/linux/files/virtio.config",
        "CONFIG_IGB=y",
        "CONFIG_UNWINDER_FRAME_POINTER=y"
      ]
    }
  }
]
```

## Contributing

This (alpha) project is managed on [`github`](https://github.com) at https://github.com/Linaro/squad-client-utils

Open an issue at https://github.com/Linaro/squad-client-utils/issues

Open a pull request at https://github.com/Linaro/squad-client-utils/pulls

For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](https://github.com/Linaro/squad-client-utils/blob/master/LICENSE)
