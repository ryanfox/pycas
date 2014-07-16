import os
from setuptools import setup


def read(filename):
    return open(os.path.join(os.path.dirname(__file__), filename)).read()


setup(name='pycas',
      version='0.0.3',
      author='Ryan Fox',
      author_email='ryan@foxrow.com',
      url='https://github.com/ryanfox/pycas',
      description='A pypi-downloadable version of Jon Rifkin\'s pycas client.',
      license='Apache 2.0',
      keywords='CAS authentication',
      packages=['pycas'],
      long_description=read('README.rst'),
      classifiers=['Topic :: System :: Systems Administration :: Authentication/Directory',
                   'Topic :: Utilities',
                   'License :: OSI Approved :: Apache Software License'],
      install_requires=['beautifulsoup4', 'lxml', 'itsdangerous'])
