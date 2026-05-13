from setuptools import setup, find_packages

setup(
    name="secureus",
    version="1.0.6",
    description="SecureUS Network Monitor - desktop app",
    packages=find_packages(),
    install_requires=[
        "PyQt5>=5.15",
        "numpy>=1.24",
        "pandas>=2.0",
    ],
    entry_points={
        # gui_scripts uses pythonw.exe on Windows — no black console window flash.
        # On Linux/macOS it behaves identically to console_scripts.
        "gui_scripts": [
            "secureus-monitor=secureus_app.monitor:main",
        ],
    },
    python_requires=">=3.9",
)
