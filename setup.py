from distutils.core import setup
from setuptools import find_packages
import re

with open("udi_interface/__init__.py") as meta_file:
    metadata = dict(re.findall("__([a-z]+)__\s*=\s*'([^']+)'", meta_file.read()))

setup(name='udi_interface',
    version=metadata['version'],
    description=metadata['description'],
    url=metadata['url'],
    author=metadata['author'],
    author_email=metadata['authoremail'],
    license=metadata['license'],
    packages=find_packages(),
    install_requires=[
        "paho-mqtt>=2.1.0",
        "python-dotenv",
        "markdown2",
        "netifaces",
        "requests",
        "pyisy >2.0, != 2.1.5, <3.0.0"
    ],
    python_requires='>3.9',
    zip_safe=False,
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How Mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 5 - Production/Stable',

        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: MIT License',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9', 
        'Programming Language :: Python :: 3.11'
    ])
