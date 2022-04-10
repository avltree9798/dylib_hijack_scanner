import setuptools

setuptools.setup(
    name="dylib_hijack_scanner",
    version="0.0.1",
    author="avltree9798",
    author_email="me@avltree9798.com",
    description="A small example package",
    url="https://github.com/avltree9798/dylib_hijack_scanner",
    project_urls={
        "Bug Tracker": "https://github.com/avltree9798/dylib_hijack_scanner/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: macOS",
    ],
    package_dir={"": "modules"},
    packages=setuptools.find_packages(where="dylib_hijack_scanner"),
    python_requires=">=3.7",
    install_requires=[
        'machotools==0.2.0',
        'argparse==1.4.0'
    ]
)
