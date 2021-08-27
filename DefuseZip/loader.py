import concurrent.futures
import io
from pathlib import Path
from pathlib import PosixPath
from pathlib import WindowsPath
from typing import Any
from typing import Dict
from typing import Tuple
from typing import Union
from zipfile import ZipFile

import psutil  # type: ignore


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
        self.__directory_travelsal = directory_travelsal_allowed

        self.__scan_completed: bool = False
        self.__is_dangerous: bool = False
        self.__killswitch: bool = False
        self.__symlink_found: bool = False

        self.__compressed_size: int = self.__zip_file.stat().st_size
        self.__zipsize: int = 0
        self.__ratio: float = 0.00
        self.highest_level = 0
        self.nested_zips_count = 0

        self.__output: Dict[str, Any] = {}
        self.__uncompressed_size_str: str = ""
        self.__compressed_size_str: str = ""
        self.__message: str = ""

    def __recursive_zips(
        self, zip_bytes: io.BytesIO, level: int = 0
    ) -> Tuple[int, int]:

        if (
            self.__nested_zips_limit
            and self.nested_zips_count >= self.__nested_zips_limit
            or self.__nested_levels_limit
            and self.highest_level > self.__nested_levels_limit
            or self.__killswitch
        ):
            return 0, level - 1

        toplevel = level
        with ZipFile(zip_bytes, "r") as zf:
            cur_count = 0
            for f in zf.namelist():
                if self.__killswitch:
                    return cur_count, self.__nested_levels_limit

                if "..\\" in f or "../" in f:
                    self.__directory_travelsal = True
                    continue
                # else:
                #    if Path(f).is_symlink():
                #        self.__symlink_found = True
                #        continue

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
        """
        :param bytes: int value of filesize in bytes
        :return: string representation of size (bytes to kb,mb,gb...)
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

    def is_dangerous(self) -> bool:  # dead: disable
        return self.__is_dangerous

    def has_travelsal(self) -> bool:  # dead: disable
        return self.__directory_travelsal

    def has_links(self) -> bool:  # dead: disable
        return self.__symlink_found  # pragma: no cover

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
        if self.__ratio > self.__ratio_threshold:
            self.__is_dangerous = True
        elif self.__nested_zips_limit_reached:
            self.__is_dangerous = True  # pragma: no cover
        elif self.__killswitch:
            self.__is_dangerous = True  # pragma: no cover
        elif (
            not self.__symlinks_allowed and self.__symlink_found
        ) or self.__directory_travelsal:
            self.__is_dangerous = True

    def __set_zip_output(self):
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
            "Dangerous": self.__is_dangerous,
            "Compression ratio": f"{self.__ratio:.2f}"
            + " Uncompressed size: "
            + self.__uncompressed_size_str
            + " Compressed size: "
            + self.__compressed_size_str,
            "Nested zips": self.nested_zips_count,
            "Nested levels": self.highest_level,
            "Symlinks": self.__symlink_found,
            "Directory travelsal": self.__directory_travelsal,
        }

    def scan(self) -> bool:
        """
        Scans the zip recursively and returns if the zip should be considered dangerous
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

        return self.__is_dangerous

    def output(self):
        """
        Returns information about the archive and scanning process
        :return:
        """
        self.raise_for_exception()  # pragma: no cover
        if len(self.__output) <= 0:
            print("You need to run .is_dangerous() first")  # pragma: no cover
        for k, v in self.__output.items():
            print(f"\t{k} = {v}")

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
            process = psutil.Process()
            default_cpu = process.rlimit(psutil.RLIMIT_CPU)
            default_memory = process.rlimit(psutil.RLIMIT_AS)
            default_filesize = process.rlimit(psutil.RLIMIT_FSIZE)

            with ZipFile(self.__zip_file, "r") as zip_ref:
                if zip_ref.testzip():
                    return False

                process.rlimit(psutil.RLIMIT_CPU, (max_cpu_time, max_cpu_time))
                process.rlimit(psutil.RLIMIT_AS, (max_memory, max_memory))
                process.rlimit(psutil.RLIMIT_FSIZE, (max_filesize, max_filesize))
                zip_ref.extractall(destination_path)
                try:
                    process.rlimit(psutil.RLIMIT_CPU, default_cpu)
                    process.rlimit(psutil.RLIMIT_AS, default_memory)
                    process.rlimit(psutil.RLIMIT_FSIZE, default_filesize)
                except Exception:
                    pass
        else:
            raise NotImplementedError(
                "Safe_extract not implemented for Windows"
            )  # pragma: no cover
        # except OSError as e:
        #    print('oserror:', str(e))
        #    return False

        return True  # pragma: no cover

    def raise_for_exception(self):
        if not self.__scan_completed:  # pragma: no cover
            raise Exception(
                "You have to complete a scan before using other methods"
            )  # pragma: no cover
