from distutils.core import setup

setup(name='libnetfilter',
      version='1.0',
      description='Python libnetfilter_* ctypes',
      author='Markus Koetter',
      author_email='koetter@rrzn.uni-hannover.de',
      url='..',
      packages=['libnetfilter','libnetfilter.netlink','libnetfilter.log','libnetfilter.queue', 'libnetfilter.conntrack'],
      package_dir = {'libnetfilter': 'lib'},
)

