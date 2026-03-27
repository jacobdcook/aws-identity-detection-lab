import json
from pathlib import Path

from models import CloudTrailLikeEvent


def load_json_events(path: Path) -> list[CloudTrailLikeEvent]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("expected JSON array")
    return [CloudTrailLikeEvent.from_dict(x) for x in raw]
