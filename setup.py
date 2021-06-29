from setuptools import setup
import re

def get_property(prop):
    result = re.search(r'{}\s*=\s*[\'"]([^\'"]*)[\'"]'.format(prop), open('DefuseZip/__init__.py').read())
    return result.group(1)

with open("README.md", 'r') as f:
    long_description = f.read()

setup(
    name='DefuseZip',
    version=get_property('__version__'),
    description='Gathers information on a zip, mainly for seeing wether the zip could be considered malicious (Zipbomb, travelsal etc.). Work in progress.',
    long_description=long_description,
    long_description_content_type="text/markdown",
    license='MIT',
    author='Tony Rintala',
    author_email='rintala.tony@gmail.com',
    url="https://github.com/kuviokelluja/DefuseZip",
    packages=['DefuseZip'],
    install_requires=['psutil'],
)
