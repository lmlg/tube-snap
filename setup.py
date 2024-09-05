import os

from setuptools import setup

requirements = []

setup(
    name='tube',
    version='0.0.1',
    author='Canonical LTD',
    author_email='luciano.logiudice@canonical.com',
    packages=['src'],
    install_requires=''.join(requirements),
    include_package_data=True,
    zip_safe=True,
    licence='AGPL - 3',
    keywords='snap linux ubuntu storage spdk',
    classifiers=[
        'Intended Audience :: Developers',
        'Natural Language :: English'
    ],
    test_suite='tests',
    scripts=['bin/tube'],
)

