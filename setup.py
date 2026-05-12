from setuptools import setup, find_packages

setup(
    name="secureus",
    version="1.0.3",
    description="SecureUS Network Monitor - desktop app",
    packages=find_packages(),
    install_requires=[
        "PyQt5>=5.15",
        "numpy>=1.24",
        "pandas>=2.0",
    ],
    entry_points={
        "console_scripts": [
            "secureus-monitor=secureus_app.monitor:main",
        ],
    },
    python_requires=">=3.9",
)
