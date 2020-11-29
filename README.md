# SecureZip
 
## Table of contents
* [Description and general info](#description--general-info)
   * [Installation](#installation)
   * [Usage](#usage)
   * [Example output](#example-output-from-output-after-calling-scan---bool)

## Description / General info
I couldn't find an opensource ZipBomb blocker, so this is my attempt at making one.

It is a work in progress, but the scan feature is usable and safe_extract works for linux.
### Installation:
```
pip install SecureZip
```
### Usage:
Loader parameters:
* [REQUIRED] zip_file: Path to zip
* [OPTIONAL] ratio_threshold: compression ratio threshold when to rule the zip malicious. Default = 1032
* [OPTIONAL] nested_zips_limit: Total zip count when to abort and rule the zip malicious. Default = 3
* [OPTIONAL] nested_levels_limit: Limit when to abort travelling the zips and rule the zip malicious. Default = 2
* [OPTIONAL] killswitch_seconds: Seconds to allow traversing the zip. After the limit is hit, zip is ruled malicious. Default = 1
* [OPTIONAL] symlinks_allowed: Boolean. Default = False

```
from pathlib import Path
import SecureZip

file = Path('myzip.zip')
zip = SecureZip.Loader(zip_file=file)
if zip.scan() and zip.get_compression_ratio() > 1032:
    print(zip.output())
else:
    #do something with the zip
```




### Example output from output() after calling scan() -> bool
* Single file in zip

        Dangerous: False
        Message = Success
        Compression Ratio = 0.77 Uncompressed size: 907.00 bytes Compressed size: 1.16 kilobytes
        Nested zips = 0
        Nest Levels = 0
        Symlinks = False
* Double nested zips -- with maximum nesting set to 4 : SecureZip.Loader(..., nested_zips_limit=4)

        Dangerous: True
        Message = Success
        Compression Ratio = 0.58 Uncompressed size: 922.00 bytes Compressed size: 1.55 kilobytes
        Nested zips = 5
        Nest Levels = 2
        Symlinks = False
* 97tb / 14,5kb zipbomb -- with 5s killswitch enabled to prevent long scan time : SecureZip.Loader(..., killswitch_seconds=5)

        Dangerous: True
        Message = Killswitch enabled due to too deep recursion or timeout, values collected are valid only to that point
        Compression Ratio = 125869951.52 Uncompressed size: 1.69 terabytes Compressed size: 14.45 kilobytes
        Nested zips = 1930
        Nest Levels = 100
        Symlinks = False
* 4.5pb / 46mb BAMSOFTWARE zbxl FLAT zipbomb

        Dangerous: True
        Message = Success
        Compression Ratio = 98262444.02 Uncompressed size: 4.00 petabytes Compressed size: 43.75 megabytes
        Nested zips = 0
        Nest Levels = 0
        Symlinks = False
