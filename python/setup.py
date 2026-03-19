from setuptools import setup, find_packages

setup(
    name="agent-shield",
    version="1.0.0",
    description="Security SDK for AI agents. Detect prompt injection, data exfiltration, and 30+ threats. All detection runs locally.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="texasreaper62",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries",
    ],
    keywords="ai security prompt-injection agent llm protection shield",
)
