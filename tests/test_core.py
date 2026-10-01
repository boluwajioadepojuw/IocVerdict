from ioc_intel.classify import kind_of
from ioc_intel.score import verdict_score
from ioc_intel.attck import map_findings
from ioc_intel.report import to_text, to_json


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
