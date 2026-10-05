from pathlib import Path


def test_server_image_installs_oauth_form_parser():
    """The shipped /oauth/token endpoint parses form-encoded RFC 8693 input.

    Source-tree environments install the full requirements file, so only the
    reduced server image exposed this missing runtime dependency. Keep the image
    contract explicit; deleting it makes the real gateway mint return HTTP 500.
    """
    dockerfile = (Path(__file__).resolve().parent.parent / "Dockerfile.server").read_text()
    assert '"python-multipart>=0.0.9"' in dockerfile
