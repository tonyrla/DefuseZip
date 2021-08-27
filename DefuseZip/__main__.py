import sys
from argparse import ArgumentParser
from pathlib import Path

from DefuseZip.loader import DefuseZip


class ArgParser(ArgumentParser):
    def error(self, message):  # dead: disable
        print(message)
        self.print_help()
        sys.exit(1)


args = ArgParser(description="")
args.add_argument("--file", "-f", type=str, help="Path to zip")
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

if "--safe_extract" in sys.argv or "-se" in sys.argv:
    group = args.add_argument_group(description="Arguments for --safe_extract")
    group.add_argument("--destination", "-d", type=str, help="Target directory")
    group.add_argument(
        "--max_cpu_time", "-mc", type=int, default=5, help="Limit CPU time in seconds"
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
filename = None
if not opts.file:
    args.print_help()
    sys.exit(1)
else:
    filename = Path(opts.file)
    if not filename.exists():
        print(f"File not found: {opts.file}")
        sys.exit(1)

if opts.safe_extract and not opts.destination:
    print("--destination PATH required with --safe_extract")
    sys.exit(1)

zip = DefuseZip(
    filename,
    opts.ratio_threshold,
    opts.nested_zips_limit,
    opts.nested_levels_limit,
    opts.killswitch_seconds,
    opts.symlinks_allowed,
    opts.directory_travelsal_allowed,
)
zip.scan()
zip.output()

if opts.safe_extract:
    target_path = Path(opts.destination)

    zip.safe_extract(target_path, opts.max_cpu_time, opts.max_memory, opts.max_filesize)
