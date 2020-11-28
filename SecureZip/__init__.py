# __init__.py
from pathlib import PurePath, PosixPath, WindowsPath, Path
from typing import Union
from zipfile import ZipFile
import psutil, io, time, os
import concurrent.futures


# Version
__version__ = "0.1"

killswitch = False
symlink_found = False
current_level = 0
current_zips = 0

class Loader:
    def __init__(self, zip_file: Union[PurePath, PosixPath, WindowsPath], ratio_threshold: int = 1032,
                     nested_zips_limit: int = None, nested_levels_limit: int = 3, killswitch_seconds: int = 5):
        """

        :param zip_file: Path to zip
        :param ratio_threshold: compression ratio threshold when to call the zip malicious
        :param nested_zips_limit: Total zip count when to abort. !Aborting will mark the zip as malicious!
        :param nested_levels_limit: Limit when to abort when travelling inside zips. You REALLY don't want to try higher
         than 3. !Aborting will mark the zip as malicious!
        """
        self.zip_file = zip_file
        self.ratio_threshold = ratio_threshold
        self.nested_zips_limit = nested_zips_limit
        self.ss=0
        self.nested_levels_limit = nested_levels_limit
        self.killswitch_seconds = killswitch_seconds
        self.__output = {}


    def __recursive_zips(self, zip_bytes: io.BytesIO, count: int = 0, level: int = 0, zipfiles_limit: int = None, levels_limit: int = None) -> (int, int):
        global killswitch, symlink_found, current_zips,current_level
        #print('\tlevel:',level)
        if zipfiles_limit and count >= zipfiles_limit:
            return 0, level -1
        if level > levels_limit or killswitch:
            return 1, level -1
        toplevel = level
        with ZipFile(zip_bytes, 'r') as zf:
            cur_count = 0
            for f in zf.namelist():
                if killswitch:
                    return 1, levels_limit

                if os.path.islink(f):
                    symlink_found = True

                if f.endswith('.zip'):
                    cur_count += 1
                    zfiledata = io.BytesIO(zf.read(f))
                    a,b = self.__recursive_zips(zfiledata, cur_count, level= toplevel + 1, zipfiles_limit= zipfiles_limit, levels_limit=levels_limit)
                    cur_count += a
                    if b>toplevel:
                        toplevel = b
                else:
                    self.ss += zf.getinfo(f).file_size
        current_level = toplevel
        current_zips = cur_count
        return cur_count, toplevel


    @classmethod
    def format_bytes(cls,size):
        n = 0
        power_labels = {0: '', 1: 'kilo', 2: 'mega', 3: 'giga', 4: 'tera', 5: 'peta', 6: 'exa'}
        while size >= 1024:
            size /= 1024
            n += 1
        return f'{size:.2f}' + " " + power_labels[n] + 'bytes'


    def is_dangerous(self) -> bool:
        global killswitch, symlink_found, current_zips, current_level
        nested_zips = False
        global ss
        if not self.zip_file.exists():
            raise FileNotFoundError

        with open(self.zip_file, 'rb') as f:
            zdata = io.BytesIO(f.read())
            tasks = []
            with concurrent.futures.ThreadPoolExecutor() as executor:
                try:
                    tasks.append(executor.submit(self.__recursive_zips, zdata, 0, zipfiles_limit=self.nested_zips_limit, levels_limit=self.nested_levels_limit))
                    for future in concurrent.futures.as_completed(tasks,timeout=self.killswitch_seconds):
                        result = future.result(timeout=self.killswitch_seconds)
                except concurrent.futures.TimeoutError:
                    for task in tasks:
                        killswitch = True
                        task.cancel()

            if killswitch:
                count = -1
                toplevel = -1
            else:
                count = result[0]
                toplevel = result[1]
            if count > 3:
                nested_zips = True
            with ZipFile(zdata) as zf:
                compression = sum(z.compress_size for z in zf.infolist())


        ratio = self.ss / compression

        try:
            compression = Loader.format_bytes(compression)
            uncompressed_size = Loader.format_bytes(self.ss)
        except KeyError:
            uncompressed_size = 'TOO LARGE TO SHOW'
        if not killswitch:
            message = 'Aborted due to too deep recursion' if toplevel>self.nested_levels_limit else 'Success'
        else:
            message = 'Killswitch enabled due to too deep recursion or timeout, values collected are valid only to that point'
            count = current_zips
            toplevel = current_level

        self.__output = {'Message':message,'Compression Ratio': f'{ratio:.2f}' + ' Uncompressed size: ' + uncompressed_size + ' Compressed size: ' + compression, 'Nested zips': count, 'Nest Levels': toplevel,
                         'Symlinks':symlink_found}

        if ratio > self.ratio_threshold or nested_zips or killswitch:
            return True
        return False

    def output(self):
        for k,v in self.__output.items():
            print('\t{} = {}'.format(k,v))

    def safe_extract(self, zip_file: Union[PurePath, PosixPath, WindowsPath],
                     destination_path: Union[PurePath, PosixPath,
                                             WindowsPath], max_cpu_time: int = 5, max_memory: int = 134217728,
                     max_filesize: int = 134217728) -> bool:

        if not zip_file.exists():
            raise FileNotFoundError
        if psutil.POSIX:
            process = psutil.Process()
            default_cpu = process.rlimit(psutil.RLIMIT_RLIMIT_CPU)
            default_memory = process.rlimit(psutil.RLIMIT_RLIMIT_AS)
            default_filesize = process.rlimit(psutil.RLIMIT_RLIMIT_FSIZE)

            with ZipFile(zip_file) as zip_ref:
                if zip_ref.testzip():
                    return False

                process.rlimit(psutil.RLIMIT_RLIMIT_CPU, (max_cpu_time, max_cpu_time))
                process.rlimit(psutil.RLIMIT_RLIMIT_AS, (max_memory, max_memory))
                process.rlimit(psutil.RLIMIT_RLIMIT_FSIZE, (max_filesize, max_filesize))
            zip_ref.extractall(destination_path)
            process.rlimit(psutil.RLIMIT_RLIMIT_CPU, default_cpu)
            process.rlimit(psutil.RLIMIT_RLIMIT_AS, default_memory)
            process.rlimit(psutil.RLIMIT_RLIMIT_FSIZE, default_filesize)
        else:
            raise NotImplemented
        return True
