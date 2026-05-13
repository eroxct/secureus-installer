from setuptools import setup, find_packages

setup(
    name="secureus",
    version="1.0.8",
    description="SecureUS Network Monitor - desktop app",
    packages=["secureus_app"],
    package_dir={"secureus_app": "secureus_app"},
    package_data={"secureus_app": ["*.py"]},
    install_requires=[
        "PyQt5>=5.15",
        "numpy>=1.24",
        "pandas>=2.0",
    ],
    entry_points={
        "gui_scripts": [
            "secureus-monitor=secureus_app.monitor:main",
        ],
    },
    python_requires=">=3.9",
)
