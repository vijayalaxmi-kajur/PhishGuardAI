from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="phishguard",
    version="1.0.0",
    author="PhishGuardAI Security Team",
    author_email="support@phishguard.ai",
    description="Official Python SDK for PhishGuardAI Phishing & Threat Intelligence Detection",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/phishguard/phishguard-python",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=[],
)

