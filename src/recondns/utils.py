import json
from datetime import datetime


def save_json(obj, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def load_json(path):
    import json

    with open(path, encoding="utf-8") as f:
        return json.load(f)


def make_snapshot_filename(domain):
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    return f"{domain}_snapshot_{ts}.json"
