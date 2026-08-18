from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict


class SourceRef(BaseModel):
    """Stable locator and integrity metadata for an input record."""

    model_config = ConfigDict(extra="forbid")

    source_type: Literal["opensearch_hit", "wazuh_json", "constructed"]
    index: str | None = None
    document_id: str | None = None
    provider: str | None = None
    channel: str | None = None
    record_id: str | None = None
    raw_digest: str | None = None

    @property
    def locator(self) -> str:
        if self.index and self.document_id:
            return f"{self.index}:{self.document_id}"
        if self.document_id:
            return self.document_id
        if self.raw_digest:
            return f"sha256:{self.raw_digest}"
        return "constructed"
