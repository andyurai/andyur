"""Actual Kubernetes SDK transport, not a mocked patch method.

API-server application and conflict enforcement are separately live-gated.
This consumer records the bytes/media type the installed SDK really sends.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from kubernetes import client

from andyur.server.kubernetes_deployments import DeploymentsApi


def test_sdk_sends_atomic_identity_tests_and_exact_template_replacement():
    requests = []
    expected = {"metadata": {"uid": "original", "resourceVersion": "42"}}
    template = {"metadata": {"labels": {"app": "checkout"}},
                "spec": {"containers": [{"name": "app", "image": "good"}]}}

    class Consumer(BaseHTTPRequestHandler):
        def do_PATCH(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append((self.path, self.headers["Content-Type"], body))
            encoded = json.dumps({**expected, "spec": {"template": template}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Consumer)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    configuration = client.Configuration()
    configuration.host = f"http://127.0.0.1:{server.server_port}"
    try:
        with client.ApiClient(configuration) as transport:
            adapter = DeploymentsApi.__new__(DeploymentsApi)
            adapter._apps = client.AppsV1Api(transport)
            returned = adapter.patch_deployment_template("fixture", "checkout",
                                                         template, expected=expected)
        assert returned["spec"]["template"] == template
        assert len(requests) == 1
        path, media_type, operations = requests[0]
        assert path.startswith("/apis/apps/v1/namespaces/fixture/deployments/checkout?")
        assert media_type == "application/json-patch+json"
        assert operations == [
            {"op": "test", "path": "/metadata/uid", "value": "original"},
            {"op": "test", "path": "/metadata/resourceVersion", "value": "42"},
            {"op": "replace", "path": "/spec/template", "value": template}]
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
