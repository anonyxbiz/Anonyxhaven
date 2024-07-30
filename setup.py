from setuptools import setup, find_packages

# Read the requirements from the requirements.txt file
with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name="Anonyxhaven",
    version="1.0.5",
    description="Anonyxhaven - an asynchronous web framework built on top of Aiohttp, designed to implement custom security, performance, and efficiency for deploying Python applications. It offers a robust set of features for handling requests, managing security, and serving static and dynamic content in a performant manner.",
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author="Anonyxbiz",
    author_email="anonyxbiz@gmail.com",
    url="https://github.com/anonyxbiz/Anonyxhaven",
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    py_modules=['Anonyxhaven'],
    python_requires='>=3.6',
)
