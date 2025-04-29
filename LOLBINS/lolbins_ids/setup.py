from setuptools import setup, find_packages

setup(
    name="lolbins_ids",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "flask",
        "flask-socketio",
        "pymongo",
        "psutil",
        "pywin32"
    ],
)