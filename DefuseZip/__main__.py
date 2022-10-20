import sys
import zipfile
from argparse import ArgumentParser
from argparse import Namespace
from pathlib import Path
from typing import List

import psutil
from loguru import logger

from DefuseZip.loader import DefuseZip
from DefuseZip.loader import MaliciousFileException


class ArgParser(ArgumentParser):
    def error(self, message):  # dead: disable
        print(message)
        self.print_help()
        raise SystemExit(1)


def main():
    opts = parse_arguments()
    return launch(opts)


def parse_arguments():
    args = ArgParser(description="")
    args.add_argument("--file", "-f", type=str, help="Path to zip")
    args.add_argument(
        "logtofile",
        default=False,
        action="store_true",
        help="Log output to file",
    )
    args.add_argument(
        "--version",
        "-v",
        dest="vercheck",
        action="store_true",
    )
    args.add_argument(
        "--ratio_threshold",
        "-rt",
        type=int,
        default=1032,
        help="Compression ratio threshold when to rule the zip malicious.",
    )
    args.add_argument(
        "--nested_zips_limit",
        "-nz",
        type=int,
        default=3,
        help="Total zip count when to abort and rule the zip malicious.",
    )
    args.add_argument(
        "--nested_levels_limit",
        "-nl",
        type=int,
        default=3,
        help="Limit when to abort travelling the zips and rule the zip malicious.",
    )
    args.add_argument(
        "--killswitch_seconds",
        "-ks",
        type=int,
        default=3,
        help="Seconds to allow traversing the zip. After the limit is hit, zip is ruled malicious.",
    )
    args.add_argument(
        "--symlinks_allowed",
        "-sl",
        type=bool,
        default=False,
        help="Boolean to toggle symlinks protection",
    )
    args.add_argument(
        "--directory_travelsal_allowed",
        "-dt",
        type=bool,
        default=False,
        help="Boolean to toggle directory travelsal protection",
    )
    args.add_argument(
        "--safe_extract",
        "-se",
        dest="safe_extract",
        default=False,
        action="store_true",
        help="Toggle to attempt extracting",
    )

    args.add_argument("--destination", "-d", type=str, help="Target directory")
    if "--safe_extract" in sys.argv or "-se" in sys.argv:
        group = args.add_argument_group(description="Arguments for --safe_extract")
        group.add_argument(
            "--max_cpu_time",
            "-mc",
            type=int,
            default=5,
            help="Limit CPU time in seconds",
        )
        group.add_argument(
            "--max_memory",
            "-mm",
            type=int,
            default=134217728,
            help="Maximum memory for the process to have for the extraction",
        )
        group.add_argument(
            "--max_filesize",
            "-mf",
            type=int,
            default=134217728,
            help="Maximum single file size",
        )

    opts = args.parse_args()
    if not opts.file:
        args.print_help()
        raise SystemExit(1)
    return opts


def verify_options(opts: Namespace, filename: Path):
    if opts.logtofile:
        logger.add(
            Path("logs") / (filename.name + ".log"),
            encoding="utf8",
            serialize=False,
            level="INFO",
            enqueue=True,
            backtrace=True,
            diagnose=True,
            catch=True,
        )
    if opts.safe_extract and not opts.destination:
        print("--destination PATH required with --safe_extract")
        raise SystemExit(1)

    if opts.safe_extract and not psutil.LINUX:
        raise NotImplementedError("Only implemented for Linux OS")

    if opts.symlinks_allowed and not psutil.LINUX:
        raise NotImplementedError("Only implemented for Linux OS")


def launch(opts: Namespace) -> int:
    filename = None

    if opts.vercheck:
        from DefuseZip import __version__

        print(f"DefuseZip v{__version__}")
        raise SystemExit(1)

    filename = Path(opts.file)
    if not filename.exists():
        print(f"File/Folder not found: {opts.file}")
        raise SystemExit(1)

    verify_options(opts, filename)

    files: List[Path] = []
    if filename.is_file():
        files.append(filename)
    else:
        for f in filename.glob("*.*"):
            if zipfile.is_zipfile(f):
                files.append(f)
    return scan_files(files, opts)


def scan_files(files: List[Path], opts: Namespace) -> int:
    for file in files:

        target_zip = DefuseZip(
            file,
            opts.ratio_threshold,
            opts.nested_zips_limit,
            opts.nested_levels_limit,
            opts.killswitch_seconds,
            opts.symlinks_allowed,
            opts.directory_travelsal_allowed,
        )
        try:
            target_zip.scan()
        except MaliciousFileException:
            sys.tracebacklimit = 0

        target_zip.output()

        if opts.safe_extract:
            target_path = Path(opts.destination)

            target_zip.safe_extract(
                target_path, opts.max_cpu_time, opts.max_memory, opts.max_filesize
            )
        else:
            if opts.destination and not target_zip.is_dangerous:
                target_zip.extract_all(Path(opts.destination) / Path(file).stem)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
