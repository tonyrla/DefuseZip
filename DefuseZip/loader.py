import concurrent.futures
import io
import sys
from functools import partialmethod
from pathlib import Path
from pathlib import PosixPath
from pathlib import WindowsPath
from typing import Any
from typing import Dict
from typing import Optional
from typing import Tuple
from typing import Union
from zipfile import ZipFile

import psutil
from loguru import logger

from DefuseZip.utils.managers import set_rlimit  # type: ignore


class PreRequisitesNotMetError(Exception):
    ...


logger.remove()
logger = logger.opt(depth=-1)
logger.level("malicious", no=50, icon="❌", color="<red>")
logger.level("safe", no=50, icon="✔️", color="<green>")
logger.add(
    sys.stderr,
    colorize=True,
    filter=lambda record: all(
        level not in record["level"].name for level in ["malicious", "safe"]
    ),
)
logger.add(
    sys.stderr,
    colorize=True,
    filter=lambda record: "file" in record["extra"]
    and "malicious" in record["level"].name,
    format="<green>{time:YYYY-MM-DD HH:mm:SS}</green> <white>|</white> <red>{level: <9} </red><white>|</white> <red>{extra[file]: <20}</red> <white>|</white> {level.icon: <3} {message}",
    level="malicious",
)
logger.add(
    sys.stderr,
    colorize=True,
    filter=lambda record: "file" in record["extra"] and "safe" in record["level"].name,
    format="<green>{time:YYYY-MM-DD HH:mm:SS}</green> <white>|</white> <white>{level: <9} </white><white>|</white> <white>{extra[file]: <20}</white> <white>|</white> {level.icon: <3} {message}",
    level="malicious",
)
logger.__class__.malicious = partialmethod(logger.__class__.log, "malicious")
logger.__class__.safe = partialmethod(logger.__class__.log, "safe")


class MaliciousFileException(Exception):
    ...


class DefuseZip:
    def __init__(
        self,
        zip_file: Union[Path, PosixPath, WindowsPath],
        ratio_threshold: int = 1032,
        nested_zips_limit: int = 3,
        nested_levels_limit: int = 3,
        killswitch_seconds: int = 3,
        symlinks_allowed: bool = False,
        directory_travelsal_allowed: bool = False,
    ):
        """
        DefuseZip initializer, loads the zip and sets the arguments
        :param zip_file: Path to zip
        :param ratio_threshold: compression ratio threshold when to call the zip malicious
        :param nested_zips_limit: Total zip count when to abort. !Aborting will mark the zip as malicious!
        :param nested_levels_limit: Limit when to abort when travelling inside zips. !Aborting will mark the zip as
        malicious!
        :param killswitch_seconds: Seconds to allow traversing the zip, before hitting killswitch to prevent hangs
        :param symlinks_allowed: Boolean. Default = False
        :param directory_travelsal_allowed: Boolean. Default = False
        """
        if not Path(zip_file).exists():
            raise FileNotFoundError(zip_file)
        self.__killswitch_seconds = killswitch_seconds
        self.__ratio_threshold = ratio_threshold
        self.__nested_zips_limit = nested_zips_limit
        self.__symlinks_allowed = symlinks_allowed
        self.__nested_levels_limit = nested_levels_limit
        self.__zip_file = zip_file
        self.__directory_travelsal_allowed = directory_travelsal_allowed

        self.__scan_completed: bool = False
        self.__is_dangerous: bool = False
        self.__killswitch: bool = False
        self.__symlink_found: bool = False
        self.__directory_travelsal = False

        self.__compressed_size: int = self.__zip_file.stat().st_size
        self.__zipsize: int = 0
        self.__ratio: float = 0.00
        self.highest_level = 0
        self.nested_zips_count = 0

        self.__output: Dict[str, Any] = {}
        self.__uncompressed_size_str: str = ""
        self.__compressed_size_str: str = ""
        self.__message: str = ""

    def should_return_from_recursion(self) -> bool:
        if self.__killswitch:
            return True
        if self.__nested_zips_limit and (
            self.nested_zips_count >= self.__nested_zips_limit
            or self.highest_level > self.__nested_levels_limit
        ):
            return True
        return False

    def should_continue_recursion(self, filename: str) -> bool:
        if any(travelsal in filename for travelsal in ("../", "..\\")):
            self.__directory_travelsal = True
            return True
        if psutil.LINUX and Path(filename).is_symlink():  # pragma: no cover
            self.__symlink_found = True
            return True
        return False

    def __recursive_zips(
        self, zip_bytes: io.BytesIO, level: int = 0
    ) -> Tuple[int, int]:
        """[summary]

        Args:
            zip_bytes (io.BytesIO): [description]
            level (int, optional): [description]. Defaults to 0.

        Returns:
            Tuple[int, int]: [description]
        """
        if self.should_return_from_recursion():
            return 0, level - 1

        toplevel = level
        with ZipFile(zip_bytes, "r") as zf:
            cur_count = 0
            for f in zf.namelist():
                if self.__killswitch:
                    return cur_count, self.__nested_levels_limit

                if self.should_continue_recursion(f):
                    continue

                if f.endswith(".zip"):
                    cur_count += 1
                    zfiledata = io.BytesIO(zf.read(f))
                    a, b = self.__recursive_zips(zfiledata, level=level + 1)
                    cur_count += a
                    if b > self.highest_level:
                        toplevel = b
                        self.highest_level = b
                    self.nested_zips_count = cur_count
                else:
                    self.__zipsize += zf.getinfo(f).file_size

        return cur_count, toplevel

    @classmethod
    def format_bytes(cls, filesize_bytes: Union[int, float]) -> str:
        """[summary]

        Args:
            filesize_bytes (Union[int, float]): int value of filesize in bytes

        Returns:
            str: string representation of size (bytes to kb,mb,gb...)
        """

        n = 0
        size_labels = {
            0: "",
            1: "kilo",
            2: "mega",
            3: "giga",
            4: "tera",
            5: "peta",
            6: "exa",
        }
        while filesize_bytes >= 1024:
            filesize_bytes /= 1024
            n += 1
        return f"{filesize_bytes:.2f}" + " " + size_labels[n] + "bytes"

    @property
    def is_dangerous(self) -> bool:
        return self.__is_dangerous

    @property
    def has_travelsal(self) -> bool:
        return self.__directory_travelsal

    @property
    def has_links(self) -> bool:
        return self.__symlink_found

    def _recursive_nested_zips_check(self):
        """Scans the zip file for nested zips

        Returns:
            bool: True if limit has been reached, False if not.
        """

        with open(self.__zip_file, "rb") as f:
            zdata = io.BytesIO(f.read())
            with concurrent.futures.ThreadPoolExecutor() as executor:
                try:
                    future = executor.submit(self.__recursive_zips, zdata, 0)
                    future.result(timeout=self.__killswitch_seconds)
                except concurrent.futures.TimeoutError:
                    self.__killswitch = True

            if (
                self.__nested_zips_limit
                and self.nested_zips_count > self.__nested_zips_limit
            ):
                self.__nested_zips_limit_reached = True  # pragma: no cover
            else:
                self.__nested_zips_limit_reached = False  # pragma: no cover

    def __set_zip_status(self):
        """[summary]"""
        ratio_check = self.__ratio > self.__ratio_threshold
        symlinks_check = not self.__symlinks_allowed and self.__symlink_found
        travelsal_check = (
            self.__directory_travelsal and not self.__directory_travelsal_allowed
        )
        if any(
            (
                ratio_check,
                symlinks_check,
                travelsal_check,
                self.__killswitch,
                self.__nested_zips_limit_reached,
            )
        ):
            self.__is_dangerous = True

    def __set_zip_output(self):
        """[summary]"""
        if not self.__killswitch:
            self.__message = (
                f"Aborted due to too deep recursion {self.highest_level}>{self.__nested_levels_limit})"
                if self.highest_level > self.__nested_levels_limit
                else "Success"
            )
        else:
            self.__message = (
                "Killswitch enabled due to too deep recursion or timeout, "
                "values collected are valid only to that point"
            )

        try:
            self.__compressed_size_str = DefuseZip.format_bytes(self.__compressed_size)
            self.__uncompressed_size_str = DefuseZip.format_bytes(self.__zipsize)
        except KeyError:  # pragma: no cover
            self.__uncompressed_size_str = "TOO LARGE TO SHOW"

        self.__output = {
            "Message": self.__message,
            "Dangerous": self.is_dangerous,
            "Compression ratio": f"{self.__ratio:.2f}"
            + " Compressed size: "
            + self.__compressed_size_str,
            "Uncompressed size": self.__uncompressed_size_str,
            "Nested zips": self.nested_zips_count,
            "Nested levels": self.highest_level,
            "Symlinks": self.has_links,
            "Directory travelsal": self.has_travelsal,
        }

    def scan(self) -> bool:
        """
        Scans the zip recursively and returns if the zip should be considered dangerous
        True if dangerous, False if not.
        :return: boolean
        """
        if not self.__zip_file.exists():
            raise FileNotFoundError

        self._recursive_nested_zips_check()

        try:
            self.__ratio = self.__zipsize / self.__compressed_size
        except ZeroDivisionError:  # pragma: no cover
            self.__ratio = 0.00

        self.__scan_completed = True

        self.__set_zip_status()
        self.__set_zip_output()

        if self.__is_dangerous:
            raise MaliciousFileException(self.__zip_file.name)

        return self.__is_dangerous

    def output(self):
        """
        Returns information about the archive and scanning process
        :return:
        """
        self.raise_for_exception()  # pragma: no cover
        if not self.__scan_completed:
            raise PreRequisitesNotMetError(
                "You need to run a scan first, to get output"
            )  # pragma: no cover
        with logger.contextualize(file=self.__zip_file.name):
            output = logger.safe if not self.__is_dangerous else logger.malicious
            for k, v in self.__output.items():
                output(f"\t{k} = {v}")
            output(f"\tLocation: {self.__zip_file.resolve()}\n")

    def get_compression_ratio(self):  # dead: disable
        """
        Returns the zip's compression ratio rounded to 2 decimals
        :return: str
        """
        return f"{self.__ratio:.2f}"  # pragma: no cover

    def safe_extract(
        self,
        destination_path: Union[Path, PosixPath, WindowsPath],
        max_cpu_time: int = 5,
        max_memory: int = 134217728,
        max_filesize: int = 134217728,
    ) -> bool:
        """
        Just in case the scan didn't pick up zip being malicious, this function will be the last line defence.
        If the extraction process goes over the given values, an exception is thrown and the extraction is cancelled.
        :param destination_path:
        :param max_cpu_time: Maximum time for the process to have for the extraction
        :param max_memory:  Maximum memory for the process to have for the extraction
        :param max_filesize: Maximum single file size allowed to be created
        :return: boolean stating the success
        """

        # try:
        self.raise_for_exception()  # pragma: no cover

        if not self.__zip_file.exists():  # pragma: no cover
            raise FileNotFoundError
        if psutil.LINUX:  # pragma: no cover

            with ZipFile(self.__zip_file, "r") as zip_ref:
                if zip_ref.testzip():
                    return False

                with set_rlimit(max_cpu_time, max_memory, max_filesize):
                    zip_ref.extractall(destination_path)
        else:
            raise NotImplementedError(
                "Safe_extract not implemented only for Linux"
            )  # pragma: no cover

        return True  # pragma: no cover

    def raise_for_exception(self):
        if not self.__scan_completed:  # pragma: no cover
            raise PreRequisitesNotMetError(
                "You have to complete a scan before using other methods"
            )  # pragma: no cover

    def extract_all(self, path: Optional[Path]) -> bool:  # pragma: no cover
        if path:
            path = Path(path).resolve()
        logger.info(path)
        if not self.__scan_completed:  # pragma: no cover
            if self.scan():
                raise MaliciousFileException("Scan failed")

        with ZipFile(self.__zip_file) as zip_ref:
            if len(zip_ref.filelist) <= 0:
                return False
            try:
                zip_ref.extractall(path=path)

                success = path.exists() and len(list(Path(path).iterdir())) > 0
                if success:
                    logger.info(f"Archive extracted to: {path}")
                return success
            except OSError as e:
                logger.exception(e)
                return False
