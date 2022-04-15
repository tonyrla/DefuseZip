import psutil
from loguru import logger


class set_rlimit:  # pragma: no cover
    def __init__(self, max_cpu_time: int, max_memory: int, max_filesize: int):
        self.process = psutil.Process()
        self.default_cpu = self.process.rlimit(psutil.RLIMIT_CPU)
        self.default_memory = self.process.rlimit(psutil.RLIMIT_AS)
        self.default_filesize = self.process.rlimit(psutil.RLIMIT_FSIZE)
        self.max_cpu_time = max_cpu_time
        self.max_memory = max_memory
        self.max_filesize = max_filesize

    def __enter__(self):
        self.process.rlimit(psutil.RLIMIT_CPU, (self.max_cpu_time, self.max_cpu_time))
        self.process.rlimit(psutil.RLIMIT_AS, (self.max_memory, self.max_memory))
        self.process.rlimit(psutil.RLIMIT_FSIZE, (self.max_filesize, self.max_filesize))
        return self

    def __exit__(self, exc_type, exc_value, traceback):  # dead: disable
        try:
            self.process.rlimit(psutil.RLIMIT_CPU, self.default_cpu)
            self.process.rlimit(psutil.RLIMIT_AS, self.default_memory)
            self.process.rlimit(psutil.RLIMIT_FSIZE, self.default_filesize)
        except Exception as e:
            logger.exception(e)
