import SecureZip, os
from pathlib import Path

files = {
    'Single file in zip': Path('example_zips') / 'single.zip',
    'Double nested zips': Path('example_zips') / 'nested.zip',
    '10gb / 19.5kb zipbomb': Path('example_zips') / 'medium_zipbomb.zip',
    '100gb / 9.7kb zipbomb': Path('example_zips') / 'big_zipbomb.zip',
    '97tb / 14,5kb zipbomb': Path('example_zips') / 'bigger_zipbomb.zip',
    'HUGE unknown size zipbomb': Path('example_zips') / 'huge_zipbomb.zip',
    '+250tb / 10mb BAMSOFTWARE zblg FLAT zipbomb': Path('example_zips') / 'zblg.zip',
    '+4pb / 46mb BAMSOFTWARE zbxl FLAT zipbomb': Path('example_zips') / 'zbxl.zip'
}

for text, file in files.items():
    #To completely travel the 97 Terabyte zipbomb (bigger_zipbomb.zip), you'll need ~300 second killswitch,
    # "huge_zipbomb.zip" requires prolly 5 times that much. Both of them have well over 100 000 zips
    zip = SecureZip.Loader(file, nested_levels_limit=100, killswitch_seconds=5, nested_zips_limit=100000, ratio_threshold=1032)
    print('----', text, '----')
    print('\tDangerous:',zip.scan())
    zip.output()
