from distutils.core import setup
import cryptools

setup(name='cryptools',
      version=cryptools.__version__,
      description='Toolbox for testing and attacking weak crypto implementations',
      license='MIT',
      requires=['pycrypto(>=2.6.1)'],
      provides=['cryptools', 'cryptools.impl'],
      packages=['cryptools', 'cryptools.impl'])
