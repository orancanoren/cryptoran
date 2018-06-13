from setuptools import setup, find_packages

long_description = 'Cryptoran is a Python3 based cryptographic algorithms library. It implements block ciphers, public key crypto algorithms and key exchange protocols. It is not safe right now and I would NOT suggest using it for sensitive material. I am developing the library for educational purposes only. Feel free to contribute and tinker around with the library.\n\nHappy encrypting!\n\n-orancanoren'

setup(name='cryptoran',
      description='A Python3 based cryptographic algorithms library',
      long_description=long_description,
      version='0.0.2.1',
      url='https://github.com/orancanoren/cryptoran',
      author='Oran Can Oren',
      author_email='orancanoren@gmail.com',
      license='MIT',
      packages=find_packages()
)
