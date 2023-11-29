from argparse import ArgumentParser
import logging


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def parse_args(raw_args):
    parser = ArgumentParser()

    parser.add_argument(
        "--testrun",
        required=True,
        help="The ID of the TestRun.",
    )

    parser.add_argument(
        "--filename",
        required=True,
        help="The reproducer file.",
    )

    parser.add_argument(
        "--plan",
        required=False,
        action="store_true",
        default=False,
        help="Fetch a TuxPlan reproducer rather than a TuxTest of TuxBuild reproducer.",
    )

    return parser.parse_args(raw_args)


def run(raw_args=None):
    args = parse_args(raw_args)

    logger.debug(args)

    return 0


if __name__ == "__main__":
    exit(run())
