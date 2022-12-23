import re

from setuptools import find_packages
from setuptools import setup


def get_property(prop):
    result = re.search(fr'{prop}\s*=\s*[\'"]([^\'"]*)[\'"]', open('DefuseZip/__init__.py').read())
    return result.group(1)


with open('README.md') as f:
    long_description = f.read()

setup(
    name='DefuseZip',
    version=get_property('__version__'),
    description='Gathers information on a zip, mainly for seeing wether the zip could be considered malicious (Zipbomb, travelsal etc.). Work in progress.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    license='MIT',
    author='Tony Rintala',
    author_email='rintala.tony@gmail.com',
    url='https://github.com/kuviokelluja/DefuseZip',
    packages=find_packages(include=['DefuseZip','DefuseZip.*']),
    install_requires=['psutil==5.8.0', 'loguru==0.6.0'],
    python_requires=">=3.7",
    entry_points={
        'console_scripts': ['DefuseZip=DefuseZip.__main__:main']
    }
)
