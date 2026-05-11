"""Agent Shield — Security SDK for AI Agents (Python)."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="agent-shield",
    version="14.2.2",
    author="Agent Shield Contributors",
    description="Security SDK for AI agents. Protects against prompt injection, "
                "data exfiltration, tool abuse, and 30+ other AI-specific threats.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/agent-shield/agent-shield-python",
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.8",
    install_requires=[],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    entry_points={
        "console_scripts": [
            "agent-shield=agent_shield.cli:main",
        ],
    },
    keywords="ai security prompt-injection agent llm langchain llamaindex",
)
