from DefuseZip.loader import DefuseZip
from pathlib import Path
import tempfile
import pytest


class Test_all:
    DANGEROUS = True
    SAFE = False
    testdata = [
        ("LICENSE.zip", SAFE),
        ("single.zip", SAFE),
        ("double_nested.zip", SAFE),
        ("travelsal.zip", DANGEROUS),
        ("medium_zipbomb.zip", DANGEROUS),
        ("big_zipbomb.zip", DANGEROUS),
        ("bigger_zipbomb.zip", DANGEROUS),
        ("huge_zipbomb.zip", DANGEROUS),
        ("zblg_BAMSOFTWARE.zip", DANGEROUS)
        # ,('zbxl_BAMSOFTWARE.zip', DANGEROUS)
    ]

    def test_LICENCE_no_travelsal(self):
        file = Path(__file__).parent / "example_zips" / "LICENSE.zip"
        zip = DefuseZip(
            file,
            nested_levels_limit=100,
            killswitch_seconds=5,
            nested_zips_limit=100000,
            ratio_threshold=1032,
        )
        zip.scan()
        assert not zip.has_travelsal()

    def test_travelsal_dangerous(self):
        file = Path(__file__).parent / "example_zips" / "travelsal.zip"
        zip = DefuseZip(
            file,
            nested_levels_limit=100,
            killswitch_seconds=5,
            nested_zips_limit=100000,
            ratio_threshold=1032,
        )
        zip.scan()
        assert zip.is_dangerous()

    @pytest.mark.parametrize("filename,expected", testdata)
    def test_is_safe(self, filename, expected):
        file = Path(__file__).parent / "example_zips" / filename
        zip = DefuseZip(
            file,
            nested_levels_limit=100,
            killswitch_seconds=5,
            nested_zips_limit=100000,
            ratio_threshold=1032,
        )
        zip.scan()
        assert zip.is_dangerous() == expected

    def test_safe_extract(self):
        file = Path(__file__).parent / "example_zips" / "single.zip"
        zip = DefuseZip(
            file,
            nested_levels_limit=100,
            killswitch_seconds=5,
            nested_zips_limit=100000,
            ratio_threshold=1032,
        )
        zip.scan()
        with tempfile.TemporaryDirectory() as tmpdir:
            zip.safe_extract(tmpdir,max_cpu_time=60)
            dest = Path(tmpdir)
            ex = any(dest.iterdir())
        
        assert ex
