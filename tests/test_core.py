import recondns.core as core


def test_get_dns_records():
    r = core.get_dns_records("example.com", ["A", "NS"])
    assert isinstance(r, dict)
    assert "A" in r
    assert "NS" in r


def test_crtsh_parse():
    subs = core.fetch_crtsh_subdomains("example.com")
    assert isinstance(subs, list)
