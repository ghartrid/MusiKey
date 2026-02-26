from setuptools import setup

setup(
    name="musikey",
    version="1.0.0",
    description="MusiKey — Musical Entropy Authentication",
    py_modules=["musikey"],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": ["musikey-py=musikey:main"],
    },
)
