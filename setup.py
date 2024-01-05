from setuptools import setup, find_packages

setup(
    name='allcrypt',
    version='1.4.2',  # Update with your version number
    long_description_content_type="text/markdown",
    long_description=open("allcrypt/README.md").read(),
    packages=find_packages(),
    install_requires=[
        'cryptography',
        'tqdm',
    ],
    entry_points={
        'console_scripts': [
            'allcrypt = allcrypt.main:main',
        ],
    },
)
