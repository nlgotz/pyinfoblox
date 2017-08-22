# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='ibclient',
    version='0.0.1',
    description="Access Infoblox API",
    classifiers=[],
    keywords='infoblox api infobloxapi',
    author='Nathan Gotz',
    author_email='nathan@gotz.co',
    url='https://github.com/nlgotz/pyinfoblox',
    license='Apache 2.0',
    packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
    include_package_data=True,
    package_data={
        'ibclient': ['templates/*.j2'],
    },
    zip_safe=False,
    install_requires=[
        'requests',
        'jinja2'
    ],
    setup_requires=[],
    namespace_packages=['ibclient'],
)
