from importlib.metadata import version

from cve_agent import __version__


def test_package_version_comes_from_project_metadata():
    assert __version__ == version("cve-agent")
