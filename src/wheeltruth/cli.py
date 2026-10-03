"""wheeltruth: does your built wheel/sdist actually contain what it should?"""

from __future__ import annotations

import argparse
import sys

from . import check as _check

__version__ = "0.1.0"


def _exit_code(reports):
    for rep in reports:
        for f in rep.findings:
            if f.severity in ("warning", "error"):
                return 1
    # Operational failures (unreadable artifacts) are errors too, but they
    # already surface as error findings above. Exit 2 is reserved for CLI
    # usage errors, which argparse handles itself.
    return 0


def cmd_check(args):
    reports = _check.check_artifacts(args.artifacts, project=args.project, smoke=args.smoke)
    if args.report == "md":
        sys.stdout.write(_check.render_markdown(reports))
    elif not args.quiet:
        sys.stdout.write(_check.render_text(reports))
    return _exit_code(reports)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="wheeltruth",
        description="Check that your built wheel/sdist actually contains "
                    "everything the package needs.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("check", help="check built artifacts for missing content")
    p.add_argument("artifacts", nargs="+", help=".whl and/or .tar.gz files to check")
    p.add_argument("--project", default=None,
                   help="project directory with pyproject.toml/setup.cfg/setup.py "
                        "to derive expected packages from")
    p.add_argument("--smoke", action="store_true",
                   help="install the wheel into a throwaway venv and import "
                        "top-level modules")
    p.add_argument("--report", choices=["text", "md"], default="text",
                   help="output format (default: text)")
    p.add_argument("--quiet", "-q", action="store_true",
                   help="suppress output; only the exit code signals issues")
    p.set_defaults(func=cmd_check)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
