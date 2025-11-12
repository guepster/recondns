import recondns.core as core
from unittest.mock import patch, Mock

# simulate a response object with attributes .status_code, .text, .headers
class DummyResp:
    def __init__(self, status, text, headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}

def mocked_requests_get(url, headers=None, timeout=None, allow_redirects=None):
    # mimic different hosts by url
    if "github" in url:
        return DummyResp(200, "There isn't a GitHub Pages site here.", {"server": "GitHub.com"})
    if "heroku" in url:
        return DummyResp(200, "No such app", {})
    if "s3" in url:
        return DummyResp(404, "<Error>NoSuchBucket</Error>", {"server": "AmazonS3"})
    return DummyResp(200, "Hello world", {})

@patch("recondns.core.requests.get", side_effect=mocked_requests_get)
def test_check_single_host_takeover(mock_get):
    # load signatures from package (should exist)
    sigs = core.load_takeover_signatures(path=None)
    # make a small set of hosts that our mock recognizes
    hosts = ["test.github.example", "myapp.herokuapp.example", "bucket.s3.example", "normal.example"]
    alerts = []
    for h in hosts:
        res = core.check_single_host_takeover(h, sigs, verbose=False)
        if res:
            alerts.extend(res)
    # assert we detected at least github and heroku and s3 patterns
    providers = {a.get("provider") for a in alerts}
    assert "GitHub Pages" in providers or "github_pages" in providers
    assert "Heroku" in providers or any("Heroku" in p for p in providers)
    assert any("S3" in p or "AWS" in p or "Amazon" in p for p in providers)
