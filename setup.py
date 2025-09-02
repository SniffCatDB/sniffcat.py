from setuptools import setup, find_packages

setup(
    name="sniffcat",
    version="0.1.8",
    description="Python client for SniffCat API.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Dominik 'skiop' S. <",
    author_email="ntxg@proton.me",
    url="https://github.com/yourusername/sniffcat.py",
    packages=find_packages(),
    install_requires=["requests"],
    license="MIT",
    python_requires=">=3.8",
)

