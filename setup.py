# setup.py - Package setup for Packet Analyser Visualiser

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt", "r") as f:
    requirements = [
        line.strip() for line in f
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="packet-analyser-visualiser",
    version="1.0.0",
    author="Mainul Islam Tasin",
    description="A Python tool to parse and visualise Wireshark .pcap files",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Mainul009/packet-analyser-visualiser",
    packages=find_packages(),
    install_requires=requirements,
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "packet-analyser=main:main",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
)
