from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class CloudTrailLikeEvent:
    """Minimal fields we care about for identity-style triage (lab data only)."""

    event_id: str
    event_name: str
    event_source: str
    source_ip: str
    user_agent: str
    user_identity: Mapping[str, Any]
    request_params: Mapping[str, Any]
    error_code: str | None
    aws_region: str

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "CloudTrailLikeEvent":
        ui = raw.get("userIdentity") or {}
        rp = raw.get("requestParameters") or {}
        return cls(
            event_id=str(raw.get("eventID", "")),
            event_name=str(raw.get("eventName", "")),
            event_source=str(raw.get("eventSource", "")),
            source_ip=str(raw.get("sourceIPAddress", "")),
            user_agent=str(raw.get("userAgent", "")),
            user_identity=dict(ui) if isinstance(ui, Mapping) else {},
            request_params=dict(rp) if isinstance(rp, Mapping) else {},
            error_code=raw.get("errorCode"),
            aws_region=str(raw.get("awsRegion", "")),
        )
