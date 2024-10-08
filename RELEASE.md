# UDI PG3 Python Interface Module Releases

## Version Numbering

We are using [Semantic Versioning](https://semver.org/) Which is MAJOR.MINOR.PATCH
- MAJOR - Will follow major Polyglot releases, current 2
- MINOR - Any release that adds functionality
- PATCH - Only fixes problems, no functional changes

## Release Information

We will be following methods defined [Managing releases in a repository
](https://help.github.com/en/github/administering-a-repository/managing-releases-in-a-repository)

https://pypi.org
https://test.pypi.org

Created github user udi-pg-dev to email pg-dev@universal-devices.com (Still valid?)
Created pypi and test pypi users udi-pg-dev (Still valid?)
Created pypi user Universal-Devices with email universal.devices.portal.dev@gmail.com


Documentation
https://realpython.com/documenting-python-code/
Use NumPy/SciPy Docstrings

## Generating a Release

To make a release
- Set the version in __init__.py
- Commit & push the changes
- Create a new tag version_{version}, and push the tags
- Login to github and create a release. Use the new tag.
  - This will automatically publish the new release
