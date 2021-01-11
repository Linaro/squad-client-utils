#!/usr/bin/env python3

"""

Given a bad build, find the latest good one

"""


import re
import argparse
from collections import defaultdict
from squad_client.core.models import Squad, ALL, Build
from squad_client.core.api import SquadApi
from squad_client.utils import first

def main(args):
    # Some configuration, might get parameterized later
    SquadApi.configure(args.get('squadapi_url', None))
    squad = Squad()
    getid = lambda s: int(re.search('\d+', s).group())
    group = squad.group(args.get('group', None))
    project = group.project(args.get('project', None))
    bad_suite = project.suite(args.get('suite', None))
    bad_test = args.get('test', None)
    bad_build = project.build(args.get('kernel_build', None))
    bad_env = project.environment(args.get('arch', None))

    print('Looking at the next good build in %s/%s for build %s' % (group.slug, project.slug, bad_build.version), flush=True)

    tests = squad.tests(
        build__created_at__lt=bad_build.created_at,
        suite=bad_suite.id,
        environment=bad_env.id,
        metadata__name=bad_test,
        ordering='-build_id',
        result=True,
        count=1
    )

    if len(tests):
        test = first(tests)
        build = Build(getid(test.build))
        print('%s: https://qa-reports.linaro.org/%s/%s/build/%s' % (build.version, group.slug, project.slug, build.version))
    else:
        print('No good build')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel_build", required=True,
                        help="tag or sha, e.g., next-20201204")
    parser.add_argument("--arch", required=True,
                        help="architecture, e.g., arm64")
    parser.add_argument("--group", required=True,
                        help="Group name e.g., lkft")
    parser.add_argument("--project", required=True,
                        help="Project name e.g., linux-next-master")
    parser.add_argument("--suite", required=True,
                        help="Suite name e.g., kunit")
    parser.add_argument("--test", required=True,
                        help="test name")
    parser.add_argument("--squadapi_url", default='https://qa-reports.linaro.org',
                        help="url to SQUAD server")
    args = vars(parser.parse_args())
    if args:
        main(args)
    else:
        exit(1)
