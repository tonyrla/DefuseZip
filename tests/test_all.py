from DefuseZip.loader import DefuseZip
import tempfile
from pathlib import Path
import pytest
import sys
from shutil import copy


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
        defusezip = DefuseZip(
            file,
            nested_levels_limit=100,
            killswitch_seconds=5,
            nested_zips_limit=100000,
            ratio_threshold=1032,
        )
        defusezip.scan()
        assert not defusezip.has_travelsal()

    def test_travelsal_dangerous(self):
        file = Path(__file__).parent / "example_zips" / "travelsal.zip"
        defusezip = DefuseZip(
            file,
            nested_levels_limit=100,
            killswitch_seconds=5,
            nested_zips_limit=100000,
            ratio_threshold=1032,
        )
        defusezip.scan()
        assert defusezip.is_dangerous()

    @pytest.mark.parametrize("filename,expected", testdata)
    def test_is_safe(self, filename: str, expected: bool):
        file = Path(__file__).parent / "example_zips" / filename
        defusezip = DefuseZip(
            file,
            nested_levels_limit=100,
            killswitch_seconds=5,
            nested_zips_limit=100000,
            ratio_threshold=1032,
        )
        defusezip.scan()
        assert defusezip.is_dangerous() == expected

    testdata2 = [
        ("nonexistant.zip", FileNotFoundError, False),
        ("exists_for_a_while.zip", FileNotFoundError, True),
    ]

    @pytest.mark.parametrize("filename, expected, create", testdata2)
    def test_not_found(self, filename: str, expected: bool, create: bool):
        zfile = Path(__file__).parent / "example_zips" / filename
        if create:
            cp = Path(zfile.parent / "single.zip")
            copy(cp, zfile)
        with pytest.raises(FileNotFoundError):
            defusezip = DefuseZip(
                zfile,
                nested_levels_limit=100,
                killswitch_seconds=5,
                nested_zips_limit=100000,
                ratio_threshold=1032,
            )
            if create:
                zfile.unlink()
            defusezip.scan()

    def test_output_safe(self, capsys):
        file = Path(__file__).parent / "example_zips" / "LICENSE.zip"
        defusezip = DefuseZip(
            file,
            nested_levels_limit=100,
            killswitch_seconds=5,
            nested_zips_limit=100000,
            ratio_threshold=1032,
        )
        defusezip.scan()
        defusezip.output()
        captured = capsys.readouterr()

        assert "Dangerous = False" in captured.out

    def test_safe_extract(self):
        file = Path(__file__).parent / "example_zips" / "single.zip"
        retval = False
        defusezip = DefuseZip(
            file,
            nested_levels_limit=100,
            killswitch_seconds=5,
            nested_zips_limit=100000,
            ratio_threshold=1032,
        )
        defusezip.scan()
        if sys.platform == "win32":
            with pytest.raises(NotImplementedError):
                with tempfile.TemporaryDirectory() as tmpdir:
                    retval = defusezip.safe_extract(tmpdir, max_cpu_time=60)
                    dest = Path(tmpdir)
                    ex = any(dest.iterdir())
            # expected value to true, because the real test on windows is NotImplementedError
            ex = True
            retval = True
        else:
            with tempfile.TemporaryDirectory() as tmpdir:
                defusezip.safe_extract(tmpdir, max_cpu_time=60)
                dest = Path(tmpdir)
                ex = any(dest.iterdir())

        assert ex
        assert retval

    def test_output_dangerous(self, capsys):
        file = Path(__file__).parent / "example_zips" / "travelsal.zip"
        defusezip = DefuseZip(
            file,
            nested_levels_limit=100,
            killswitch_seconds=5,
            nested_zips_limit=100000,
            ratio_threshold=1032,
        )
        defusezip.scan()
        defusezip.output()
        captured = capsys.readouterr()

        assert "Dangerous = True" in captured.out

    def test_no_scan(self, capsys):
        if sys.platform == "win32":
            assert True
            return True
        file = Path(__file__).parent / "example_zips" / "travelsal.zip"
        defusezip = DefuseZip(
            file,
            nested_levels_limit=100,
            killswitch_seconds=5,
            nested_zips_limit=100000,
            ratio_threshold=1032,
        )
        with pytest.raises(Exception):
            defusezip.safe_extract(Path.cwd())

    def test_extract_deleted_file(self, capsys):
        if sys.platform == "win32":
            assert True
            return True
        zfile = Path(__file__).parent / "example_zips" / "deleted.zip"

        cp = Path(zfile.parent / "single.zip")
        copy(cp, zfile)
        defusezip = DefuseZip(
            zfile,
            nested_levels_limit=100,
            killswitch_seconds=5,
            nested_zips_limit=100000,
            ratio_threshold=1032,
        )
        defusezip.scan()
        zfile.unlink()
        with pytest.raises(FileNotFoundError):
            with tempfile.TemporaryDirectory() as tmpdir:
                defusezip.safe_extract(Path(tmpdir))
