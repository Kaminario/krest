#
# (c) 2015 Kaminario Technologies, Ltd.
#
# This software is licensed solely under the terms of the Apache 2.0 license,
# the text of which is available at http://www.apache.org/licenses/LICENSE-2.0.
# All disclaimers and limitations of liability set forth in the Apache 2.0 license apply.
#

from setuptools import setup

desc = """The Kaminario REST (krest) is a client library \
that provides ORM like interface for working with Kaminario K2 REST API"""

long_desc = """Krest is written in Python and is aimed to provide \
rapid enablement of managing and monitoring Kaminario K2 all-flash arrays using Python.

Please see the project homepage_ for full description.

.. _homepage: https://github.com/Kaminario/krest
"""

setup(name="krest",
      version="1.3.5",
      py_modules=["krest"],
      install_requires=["requests >= 2.0.0"],
      maintainer="Zaar Hai",
      maintainer_email="haizaar@haizaar.com",
      url="https://github.com/Kaminario/krest",
      description=desc,
      long_description=long_desc,
      download_url="https://github.com/Kaminario/krest/releases",
      license="Apache 2.0",
      classifiers=[
                   'Development Status :: 5 - Production/Stable',
                   'Intended Audience :: Developers',
                   'Natural Language :: English',
                   'License :: OSI Approved :: Apache Software License',
                   'Programming Language :: Python',
                   'Programming Language :: Python :: 2.6',
                   'Programming Language :: Python :: 2.7',
                   'Programming Language :: Python :: 3.4'],
      )
