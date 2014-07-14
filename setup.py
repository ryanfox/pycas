import os
from setuptools import setup

def read(filename):
    return open(os.path.join(os.path.dirname(__file__), filename)).read()


setup(name='pycas',
      version='0.0.1',
      author='Ryan Fox',
      author_email='ryan@foxrow.com',
      description='A pypi-downloadable version of the Jasig pycas client.',
      license='Apache 2.0',
      keywords='CAS authentication',
      packages=['pycas'],
      long_description=read('README.rst'),
      classifiers=['Topic :: System :: Systems Administration :: Authentication/Directory',
                   'Topic :: Utilities',
                   'License :: OSI Approved :: Apache Software License'])
