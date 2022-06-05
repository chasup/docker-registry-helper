import pytest

from registry_helper import ImageReference


class TestParseImageReference:

    def test_no_tag_or_digest_throws(self):
        with pytest.raises(ValueError):
            ImageReference("registry.host.name/image").tag_or_digest

    def test_registry_and_image(self) -> None:
        result = ImageReference("registry.host.name/image:tag1")

        assert result.registry == "registry.host.name"
        assert result.image == "image"
        assert result.tag_or_digest == "tag1"

    def test_registry_with_port_and_image(self) -> None:
        result = ImageReference("localhost:5000/image:tag1")

        assert result.registry == "localhost:5000"
        assert result.image == "image"
        assert result.tag_or_digest == "tag1"

    def test_registry_and_repository_and_image(self) -> None:
        result = ImageReference("registry.host.name/repository/path/image:latest")

        assert result.registry == "registry.host.name"
        assert result.image == "repository/path/image"
        assert result.tag_or_digest == "latest"

    def test_registry_and_repository_and_image_and_tag(self) -> None:
        result = ImageReference("registry.host.name/repository/path/image:tag1")

        assert result.registry == "registry.host.name"
        assert result.image == "repository/path/image"
        assert result.tag_or_digest == "tag1"

    def test_registry_and_repository_and_image_and_digest(self) -> None:
        result = ImageReference("registry.host.name/repository/path/image@sha256:abcdef0123456789")

        assert result.registry == "registry.host.name"
        assert result.image == "repository/path/image"
        assert result.tag_or_digest == "sha256:abcdef0123456789"

    def test_registry_and_image_and_digest(self) -> None:
        result = ImageReference("registry.host.name/image@sha256:abcdef0123456789")

        assert result.registry == "registry.host.name"
        assert result.image == "image"
        assert result.tag_or_digest == "sha256:abcdef0123456789"
