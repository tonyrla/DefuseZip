from DefuseZip.loader import DefuseZip
from pathlib import Path
import pytest
import sys


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

    testdata2 = [
        ("nonexistant.zip", FileNotFoundError, False),
        ("exists_for_a_while.zip", FileNotFoundError, True),
    ]

    @pytest.mark.parametrize("filename, expected, create", testdata2)
    def test_not_found(self, filename, expected, create):
        zfile = Path(__file__).parent / "example_zips" / filename
        if create:
            zfile.touch()
        with pytest.raises(FileNotFoundError):
            zip = DefuseZip(
                zfile,
                nested_levels_limit=100,
                killswitch_seconds=5,
                nested_zips_limit=100000,
                ratio_threshold=1032,
            )
            if create:
                zfile.unlink()
            zip.scan()

    def test_output_safe(self, capsys):
        file = Path(__file__).parent / "example_zips" / "LICENSE.zip"
        zip = DefuseZip(
            file,
            nested_levels_limit=100,
            killswitch_seconds=5,
            nested_zips_limit=100000,
            ratio_threshold=1032,
        )
        zip.scan()
        zip.output()
        captured = capsys.readouterr()

        assert "Dangerous = False" in captured.out

    def test_output_dangerous(self, capsys):
        file = Path(__file__).parent / "example_zips" / "travelsal.zip"
        zip = DefuseZip(
            file,
            nested_levels_limit=100,
            killswitch_seconds=5,
            nested_zips_limit=100000,
            ratio_threshold=1032,
        )
        zip.scan()
        zip.output()
        captured = capsys.readouterr()

        assert "Dangerous = True" in captured.out

    def test_no_scan(self, capsys):
        if sys.platform == "win32":
            assert True
            return True
        file = Path(__file__).parent / "example_zips" / "travelsal.zip"
        zip = DefuseZip(
            file,
            nested_levels_limit=100,
            killswitch_seconds=5,
            nested_zips_limit=100000,
            ratio_threshold=1032,
        )
        with pytest.raises(Exception):
            zip.safe_extract(Path.cwd())

    def test_extract_deleted_file(self, capsys):
        if sys.platform == "win32":
            assert True
            return True
        zfile = Path(__file__).parent / "example_zips" / "deleted.zip"
        zfile.touch()
        zip = DefuseZip(
            zfile,
            nested_levels_limit=100,
            killswitch_seconds=5,
            nested_zips_limit=100000,
            ratio_threshold=1032,
        )
        zip.scan()
        zfile.unlink()
        with pytest.raises(FileNotFoundError):
            zip.safe_extract(Path.cwd())
