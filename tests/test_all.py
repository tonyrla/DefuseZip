from DefuseZip.loader import DefuseZip
from pathlib import Path
import pytest

'''
        Message = Success
        Dangerous = True
        Compression ratio = 15013168.68 Uncompressed size: 100.00 gigabytes Compressed size: 6.98 kilobytes
        Nested zips = 110
        Nested levels = 2
        Symlinks = False
        Directory travelsal = False
'''
class Test_all:
    DANGEROUS = True
    SAFE = False
    testdata = [
        ('LICENSE.zip', SAFE)
        ,('single.zip', SAFE)
        ,('double_nested.zip', SAFE)
        ,('travelsal.zip', DANGEROUS)
        ,('medium_zipbomb.zip', DANGEROUS)
        ,('big_zipbomb.zip', DANGEROUS)
        ,('bigger_zipbomb.zip', DANGEROUS)
        ,('huge_zipbomb.zip', DANGEROUS)
        ,('zblg_BAMSOFTWARE.zip', DANGEROUS)
        #,('zbxl_BAMSOFTWARE.zip', DANGEROUS)
    ]

    def test_LICENCE_no_travelsal(self):
        file = Path(__file__).parent / 'example_zips' / 'LICENSE.zip'
        zip = DefuseZip(file, nested_levels_limit=100, killswitch_seconds=5, nested_zips_limit=100000, ratio_threshold=1032)
        zip.scan()
        assert not zip.has_travelsal()

    def test_travelsal_dangerous(self):
        file = Path(__file__).parent / 'example_zips' / 'travelsal.zip'
        zip = DefuseZip(file, nested_levels_limit=100, killswitch_seconds=5, nested_zips_limit=100000, ratio_threshold=1032)
        zip.scan()
        assert zip.is_dangerous()

    @pytest.mark.parametrize("filename,expected", testdata)
    def test_is_safe(self, filename, expected):
        file = Path(__file__).parent / 'example_zips' / filename
        zip = DefuseZip(file, nested_levels_limit=100, killswitch_seconds=5, nested_zips_limit=100000, ratio_threshold=1032)
        zip.scan()
        assert zip.is_dangerous() == expected
