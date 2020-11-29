from setuptools import setup

with open("README.md", 'r') as f:
    long_description = f.read()

setup(
    name='SecureZip',
    version='0.0.1',
    description='ZipBomb scanner and safe extract. Work in progress.',
    long_description=long_description,
    license='MIT',
    author='Tony Rintala',
    author_email='rintala.tony@gmail.com',
    url="https://github.com/kuviokelluja/SecureZip",
    packages=['SecureZip'],
    install_requires=['psutil'],
)