from setuptools import setup
from pathlib import Path

requirements = [
    line.strip()
    for line in Path("requirements.txt").read_text().splitlines()
    if line.strip() and not line.startswith("#")
]

setup(
    name="nox-cli",
    version="1.0.0",
    author="nox-project",
    description="Advanced Asynchronous Cyber Threat Intelligence Framework",
    long_description=Path("README.md").read_text(),
    long_description_content_type="text/markdown",
    license="Apache-2.0",
    python_requires=">=3.8",
    py_modules=["nox"],
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "nox-cli=nox:main",
        ],
    },
    data_files=[
        ("share/nox-cli/sources", [str(p) for p in Path("sources").glob("*.json")]),
        ("share/man/man1", ["docs/nox-cli.1"]),
    ],
)
