import SecureZip
from pathlib import Path

files = {
    'Single file in zip': Path('example_zips') / 'single.zip',
    'Double nested zips': Path('example_zips') / 'nested.zip',
    '10GB zipbomb': Path('example_zips') / 'medium_zipbomb.zip',
    '100GB zipbomb': Path('example_zips') / 'big_zipbomb.zip',
    '!HUGE! zipbomb': Path('example_zips') / 'bigger_zipbomb.zip',
    'BAMSOFTWARE zblg 10mb -> 281 TB': Path('example_zips') / 'zblg.zip',
    'BAMSOFTWARE zbxl 46mb -> 4.5 PB': Path('example_zips') / 'zbxl.zip'
}

for text, file in files.items():
    zip = SecureZip.Loader(file, nested_levels_limit=5000, killswitch_seconds=5)
    print('----', text, '----')
    print('\tDangerous:',zip.is_dangerous())
    zip.output()
