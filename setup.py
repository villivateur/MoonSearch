from pathlib import Path

from setuptools import setup


BASE_DIR = Path(__file__).resolve().parent
README_PATH = BASE_DIR / "README.md"

if README_PATH.exists():
    LONG_DESCRIPTION = README_PATH.read_text(encoding="utf-8")
else:
    LONG_DESCRIPTION = "MoonSearch IP lookup web application."


setup(
    name="moonsearch",
    version="0.1.0",
    description="IP to country lookup web application built with Flask",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    packages=["moonsearch"],
    package_dir={"moonsearch": "."},
    package_data={
        "moonsearch": [
            "templates/*.html",
            "static/*",
            "cidr_database/*.csv",
            "cidr_database/ipv4/*.zone",
            "cidr_database/ipv4/.ipdeny-sync.json",
            "cidr_database/ipv6/*.zone",
            "cidr_database/ipv6/.ipdeny-sync.json",
        ]
    },
    include_package_data=True,
    install_requires=[
        "Flask",
        "gunicorn",
    ],
    python_requires=">=3.8",
    scripts=["update-cidr.py"],
)