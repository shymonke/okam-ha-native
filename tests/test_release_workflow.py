import json
import re
import tomllib
from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_publication_requires_release_tags_or_suffixed_manual_builds() -> None:
    source = (ROOT / ".github/workflows/publish-image.yml").read_text(encoding="utf-8")
    triggers = source.split("permissions:", 1)[0]
    assert 'tags: ["v*"]' in triggers
    assert "branches:" not in triggers
    assert "paths:" not in triggers
    assert "workflow_dispatch:" in triggers
    assert "tag_suffix:" in triggers
    assert "required: true" in triggers
    assert 'if [ "${GITHUB_REF_NAME#v}" != "$base" ]; then' in source
    assert 'if [ -z "${TAG_SUFFIX:-}" ]; then' in source
    assert 'echo "version=${base}-${TAG_SUFFIX}"' in source
    assert 'echo "Release tag must match the app version." >&2\n              exit 1' in source
    assert 'echo "Manual builds require a test suffix." >&2\n              exit 1' in source
    assert "ghcr.io/shymonke/okam-ha-native" in source


def test_publication_depends_on_the_same_suite_as_tests_workflow() -> None:
    directory = ROOT / ".github/workflows"
    source = (directory / "publish-image.yml").read_text(encoding="utf-8")
    tests = source.split("  tests:\n", 1)[1].split("  prepare:\n", 1)[0]
    expected = (directory / "tests.yml").read_text(encoding="utf-8").split(
        "  python:\n", 1
    )[1]
    assert tests.strip() == expected.strip()
    build = source.split("  build:\n", 1)[1].split("  publish:\n", 1)[0]
    publish = source.split("  publish:\n", 1)[1]
    assert "needs: [prepare, tests]" in build
    assert "needs: [prepare, tests, build]" in publish


def test_release_metadata_versions_agree() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    manifest = json.loads(
        (ROOT / "custom_components/okam/manifest.json").read_text(encoding="utf-8")
    )
    config = (ROOT / "okam_native_app/config.yaml").read_text(encoding="utf-8")
    version = re.search(r"^version: (.+)$", config, re.MULTILINE)
    assert version is not None
    assert project["project"]["version"] == manifest["version"] == version.group(1)
    dockerfile = (ROOT / "okam_native_app/Dockerfile").read_text(encoding="utf-8")
    assert f"ARG BUILD_VERSION={version.group(1)}\n" in dockerfile


def test_technical_instructions_describe_current_operation() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "FFmpeg repackages live H.264 into\nMPEG-TS for Home Assistant without re-encoding" in readme
    assert "re-encodes JPEG for snapshots\nand the browser MJPEG viewer" in readme
    docs = (ROOT / "okam_native_app/DOCS.md").read_text(encoding="utf-8")
    operation = docs.split("## Operation", 1)[1]
    assert "**Reconfigure**" in operation
    assert "integration entry's menu (\u22ee)" in operation
    assert "**Configure**" not in operation
