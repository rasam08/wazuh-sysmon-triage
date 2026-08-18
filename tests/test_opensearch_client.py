from typing import Any

import pytest

from wazuh_sysmon_triage.clients.opensearch_client import OpenSearchClient


def _client_with_pit_response(
    monkeypatch: pytest.MonkeyPatch,
    response: dict[str, Any],
) -> OpenSearchClient:
    client = object.__new__(OpenSearchClient)
    monkeypatch.setattr(client, "_request", lambda *_args, **_kwargs: (response, None))
    return client


def test_create_pit_returns_string_id(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client_with_pit_response(monkeypatch, {"pit_id": "pit-123"})

    assert client.create_pit("wazuh-alerts-*") == "pit-123"


@pytest.mark.parametrize("pit_id", [None, "", 123, ["pit-123"]])
def test_create_pit_rejects_missing_or_non_string_id(
    monkeypatch: pytest.MonkeyPatch,
    pit_id: object,
) -> None:
    client = _client_with_pit_response(monkeypatch, {"pit_id": pit_id})

    with pytest.raises(ValueError, match="missing pit_id"):
        client.create_pit("wazuh-alerts-*")
