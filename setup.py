from setuptools import setup, find_packages

setup(
    name='allcrypt',
    version='1.5.0',  # Update with your version number
    long_description_content_type="text/markdown",
    long_description=open("allcrypt/README.md").read(),
    packages=find_packages(),
    install_requires=[
        'cryptography',
        'tqdm',
        'psutil'
    ],
    entry_points={
        'console_scripts': [
            'allcrypt = allcrypt.main:main',
        ],
    },
    author='Pranav A.',
    author_email='prnv.school@gmail.com',
    description='Allcrypt - file/message encryption/decryption GUI with hardware token(USB) support.',
    license='MIT'
)
