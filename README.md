# DefuseZip
![Build Status](https://github.com/tonyrla/DefuseZip/actions/workflows/tox.yml/badge.svg)
[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/pre-commit/pre-commit/master.svg)](https://results.pre-commit.ci/latest/github/tonyrla/DefuseZip/main)
[![codefactor](https://www.codefactor.io/repository/github/tonyrla/defusezip/badge/main)](https://www.codefactor.io/repository/github/tonyrla/defusezip/overview/main)
[![codecov](https://codecov.io/gh/tonyrla/DefuseZip/branch/main/graph/badge.svg?token=AFSWTF0QBX)](https://codecov.io/gh/tonyrla/DefuseZip)
![codeql-analysis](https://github.com/tonyrla/DefuseZip/actions/workflows/codeql-analysis.yml/badge.svg)


----
![GitHub pull requests](https://img.shields.io/github/issues-pr/tonyrla/DefuseZip)
![GitHub issues](https://img.shields.io/github/issues-raw/tonyrla/DefuseZip)

----
![pypiversion](https://img.shields.io/pypi/v/DefuseZip)

----


## Table of contents
- [DefuseZip](#defusezip)
  - [Table of contents](#table-of-contents)
  - [Description / General info](#description--general-info)
    - [Installation:](#installation)
    - [Usage:](#usage)
      - [Command line](#command-line)
      - [Scanning the current directory](#scanning-the-current-directory)
      - [Scanning and extracting the safe zip files in currenct directory to current directory](#scanning-and-extracting-the-safe-zip-files-in-currenct-directory-to-current-directory)
      - [Python import](#python-import)
      - [Scanning and extracting everything safe zip in file progmatically](#scanning-and-extracting-everything-safe-zip-in-file-progmatically)
    - [Example output from output() after calling scan()](#example-output-from-output-after-calling-scan)

## Description / General info
I couldn't find an opensource ZipBomb blocker, so this is my attempt at making one.

It is a work in progress, but the scan feature is usable and safe_extract works for linux.

DO NOT EXTRACT THE EXAMPLE ZIPS! It will make you sad. No one wants you to be sad.

They are malicious by intent and only for testing purposes.
### Installation:
```
pip install DefuseZip
```
### Usage:

#### Command line

* DefuseZip --help

* python -m DefuseZip --help
#### Scanning the current directory
```
DefuzeZip -f .
```
#### Scanning and extracting the safe zip files in currenct directory to current directory
```
DefuseZip -f . -d .
```


#### Python import
DefuseZip arguments:
* [REQUIRED] zip_file: Path to zip
* [OPTIONAL] ratio_threshold: compression ratio threshold when to rule the zip malicious. Default = 1032
* [OPTIONAL] nested_zips_limit: Total zip count when to abort and rule the zip malicious. Default = 3
* [OPTIONAL] nested_levels_limit: Limit when to abort travelling the zips and rule the zip malicious. Default = 2
* [OPTIONAL] killswitch_seconds: Seconds to allow traversing the zip. After the limit is hit, zip is ruled malicious. Default = 1
* [OPTIONAL] symlinks_allowed: Boolean. Default = False, Linux only atm
* [OPTIONAL] directory_travelsal_allowed: Boolean. Default = False

DefuseZip methods:
* is_dangerous() -> bool
* has_travelsal() -> bool
* has_links() -> bool
* extract_all()

#### Scanning and extracting everything safe zip in file progmatically
```
import zipfile
from pathlib import Path
from typing import List

from DefuseZip.loader import DefuseZip
from DefuseZip.loader import MaliciousFileException

files: List[Path] = []
for f in Path.cwd().glob("*.*"):
    if zipfile.is_zipfile(f):
        files.append(f)

for file in files:
    zip = DefuseZip(file)
    try:
        zip.scan()
    except MaliciousFileException:
        zip.output()
        continue

    if not zip.is_dangerous:
        zip.extract_all(Path.cwd() / Path(file).stem)
```

### Example output from output() after calling scan()
* Single file in zip
```
2022-04-15 11:38:98 | safe      | single.zip           |      Message = Success
2022-04-15 11:38:98 | safe      | single.zip           |      Dangerous = False
2022-04-15 11:38:98 | safe      | single.zip           |      Compression ratio = 0.77 Compressed size: 1.16 kilobytes
2022-04-15 11:38:98 | safe      | single.zip           |      Uncompressed size = 907.00 bytes
2022-04-15 11:38:98 | safe      | single.zip           |      Nested zips = 0
2022-04-15 11:38:98 | safe      | single.zip           |      Nested levels = 0
2022-04-15 11:38:99 | safe      | single.zip           |      Symlinks = False
2022-04-15 11:38:99 | safe      | single.zip           |      Directory travelsal = False
2022-04-15 11:38:99 | safe      | single.zip           |      Location: .\tes
ts\example_zips\single.zip
```
* Double nested zips -- with maximum nesting set to 4 : DefuseZip.Loader(..., nested_zips_limit=4)
```
2022-04-15 11:38:86 | malicious | double_nested.zip    |       Message = Success
2022-04-15 11:38:86 | malicious | double_nested.zip    |       Dangerous = True
2022-04-15 11:38:86 | malicious | double_nested.zip    |       Compression ratio = 0.02 Compressed size: 871
.00 bytes
2022-04-15 11:38:86 | malicious | double_nested.zip    |       Uncompressed size = 15.00 bytes
2022-04-15 11:38:86 | malicious | double_nested.zip    |       Nested zips = 4
2022-04-15 11:38:87 | malicious | double_nested.zip    |       Nested levels = 2
2022-04-15 11:38:87 | malicious | double_nested.zip    |       Symlinks = False
2022-04-15 11:38:87 | malicious | double_nested.zip    |       Directory travelsal = False
2022-04-15 11:38:87 | malicious | double_nested.zip    |       Location: .\tes
ts\example_zips\double_nested.zip
```
* 4.5pb / 46mb BAMSOFTWARE zbxl FLAT zipbomb
```
2022-04-15 11:38:90 | malicious | zbxl_BAMSOFTWARE.zip |       Message = Success
2022-04-15 11:38:90 | malicious | zbxl_BAMSOFTWARE.zip |       Dangerous = True
2022-04-15 11:38:90 | malicious | zbxl_BAMSOFTWARE.zip |       Compression ratio = 98262444.02 Compressed si
ze: 43.75 megabytes
2022-04-15 11:38:90 | malicious | zbxl_BAMSOFTWARE.zip |       Uncompressed size = 4.00 petabytes
2022-04-15 11:38:90 | malicious | zbxl_BAMSOFTWARE.zip |       Nested zips = 0
2022-04-15 11:38:90 | malicious | zbxl_BAMSOFTWARE.zip |       Nested levels = 0
2022-04-15 11:38:90 | malicious | zbxl_BAMSOFTWARE.zip |       Symlinks = False
2022-04-15 11:38:91 | malicious | zbxl_BAMSOFTWARE.zip |       Directory travelsal = False
2022-04-15 11:38:91 | malicious | zbxl_BAMSOFTWARE.zip |       Location: .\tes
ts\example_zips\zbxl_BAMSOFTWARE.zip
```
