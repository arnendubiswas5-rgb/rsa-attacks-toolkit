from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="rsa-attacks-toolkit",
    version="0.1.0",
    description="Educational RSA cryptography attack toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="rsa-attacks-toolkit contributors",
    python_requires=">=3.11",
    packages=find_packages(exclude=["tests*", "notebooks*"]),
    install_requires=[
        "pycryptodome>=3.20.0",
        "gmpy2>=2.1.5",
        "sympy>=1.13.0",
    ],
    extras_require={
        "dev": [
            "pytest>=8.0.0",
            "pytest-cov",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Education",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="rsa cryptography attacks educational ctf",
)
