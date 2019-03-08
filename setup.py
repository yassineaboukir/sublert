#!/usr/bin/env python
from setuptools import setup

VERSION = '1.0.0'

setup_info = dict(
    name='sublert',
    version=VERSION,
    license='MIT',
    author='Yassine Aboukir',
    author_email='Hello@yassineaboukir.com',
    url='http://github.com/yassineaboukir/sublert',
    download_url='http://github.com/yassineaboukir/sublert.git',
    description='Sublert is a security and reconnaissance tool which leverages certificate transparency for the sole purpose of monitoring new subdomains deployed by specific organizations and issued TLS/SSL certificate. The tool will be scheduled to run periodically at fixed times, dates, or intervals (Ideally each day) and newly identified subdomains will be sent to Slack workspace with a notification push. Furthermore, the tool will determine resolving subdomains.',
    install_requires=['psycopg2-binary',
                      'argparse',
                      'difflib',
                      'requests',
                      'dnspython',
                      'tld',
                      'termcolor',
                      'queue'],
    project_urls={
        'Documentation': 'http://github.com/yassineaboukir/sublert',
        'Roadmap': 'https://github.com/django/django',
        'Issue Tracker': 'https://code.djangoproject.com/',
    )
