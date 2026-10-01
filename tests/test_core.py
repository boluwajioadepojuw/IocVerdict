from ioc_intel.classify import kind_of
from ioc_intel.score import verdict_score
from ioc_intel.attck import map_findings
from ioc_intel.report import to_text, to_json
from ioc_intel.enrich import urlhaus_host, _csv_listed, _cache_fresh, _cache_path, malware_bazaar


def test_kind_ipv4():
    assert kind_of("8.8.8.8") == "ipv4"


def test_kind_domain():
    assert kind_of("paypa1.com") == "domain"


def test_kind_url():
    assert kind_of("http://evil.com/x") == "url"


def test_kind_hashes():
    assert kind_of("d41d8cd98f00b204e9800998ecf8427e") == "md5"
    assert kind_of("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"
    assert kind_of("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "sha256"


def test_kind_unknown():
    assert kind_of("not an ioc") == "unknown"


def test_score_capped():
    assert verdict_score({"vt_positives": 20, "abuse_confidence": 100}) == 100


def test_score_empty():
    assert verdict_score({}) == 0


def test_attck_mapping_botnet():
    data = {"feodo_listed": True}
    mapped = map_findings(data)
    assert any(t["id"] == "T1583.001" for t in mapped)


def test_text_report():
    text = to_text("8.8.8.8", "ipv4", 40, [{"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"}])
    assert "IocVerdict" in text
    assert "40/100" in text
    assert "T1071" in text


def test_json_report():
    import json
    data = json.loads(to_json("x.com", "domain", 10, [], {}))
    assert data["indicator"] == "x.com"
    assert data["score"] == 10


def test_urlhaus_host_from_url():
    assert urlhaus_host("http://105.184.94.10:40511/bin.sh", "url") == "105.184.94.10"
    assert urlhaus_host("https://evil.example.com/login", "url") == "evil.example.com"


def test_urlhaus_host_domain_passthrough():
    assert urlhaus_host("paypa1.com", "domain") == "paypa1.com"


def test_urlhaus_host_non_url_kinds_empty():
    assert urlhaus_host("8.8.8.8", "ipv4") == ""


def test_csv_listed_finds_host():
    csv_text = '"id","dateadded","url","url_status"\n"1","2026-10-01","http://105.184.94.10:40511/bin.sh","online"\n'
    assert _csv_listed("105.184.94.10", csv_text) is True


def test_csv_listed_misses_unknown_host():
    csv_text = '"id","dateadded","url","url_status"\n"1","2026-10-01","http://1.2.3.4/x.sh","online"\n'
    assert _csv_listed("9.9.9.9", csv_text) is False


def test_mb_listed_scores():
    assert verdict_score({"mb_listed": True}) == 40


def test_mb_maps_to_malicious_file():
    mapped = map_findings({"mb_listed": True})
    assert any(t["id"] == "T1204.002" for t in mapped)


def test_malware_bazaar_skips_non_hashes(monkeypatch):
    monkeypatch.setenv("MALWAREBAZAAR_API_KEY", "test-key")
    assert malware_bazaar("8.8.8.8", "ipv4") == {}
    assert malware_bazaar("paypa1.com", "domain") == {}


def test_malware_bazaar_requires_key(monkeypatch):
    monkeypatch.delenv("MALWAREBAZAAR_API_KEY", raising=False)
    assert malware_bazaar("44d88612fea8a8f36de82e1278abb02f", "md5") == {}


def test_malware_bazaar_get_info(monkeypatch):
    monkeypatch.setenv("MALWAREBAZAAR_API_KEY", "test-key")

    class FakeResp:
        def json(self):
            return {"query_status": "ok", "data": [{"signature": "EICAR", "sha256_hash": "x"}]}

    calls = []

    def fake_post(url, **kw):
        calls.append(kw)
        return FakeResp()

    monkeypatch.setattr("ioc_intel.enrich.requests.post", fake_post)
    res = malware_bazaar("44d88612fea8a8f36de82e1278abb02f", "md5")
    assert res["mb_listed"] is True
    assert res["mb_signature"] == "EICAR"
    assert calls[0]["headers"] == {"Auth-Key": "test-key"}


def test_cache_fresh_ttl(tmp_path):
    path = str(tmp_path / "cache.csv")
    open(path, "w").write("x")
    assert _cache_fresh(path) is True
    import os
    old = 2 * 3600 + 5
    os.utime(path, (old, old))
    assert _cache_fresh(path) is False


def test_cache_path_under_tmp():
    import os
    assert _cache_path().startswith(os.path.join(os.path.sep + "tmp", "iocverdict")) or os.path.exists(os.path.dirname(_cache_path()))
