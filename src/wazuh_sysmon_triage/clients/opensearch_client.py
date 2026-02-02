# File: /wazuh-sysmon-triage/wazuh-sysmon-triage/src/wazuh_sysmon_triage/clients/opensearch_client.py

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

LOGGER = logging.getLogger(__name__)


RETRY_STATUS_CODES = {429, 502, 503}
DEFAULT_TIMEOUT = httpx.Timeout(30.0, connect=10.0)


class OpenSearchClient:
    """A client for interacting with an OpenSearch server."""

    def __init__(
        self,
        base_url: str,
        user: str,
        password: str,
        verify_tls: bool = True,
        timeout: httpx.Timeout = DEFAULT_TIMEOUT,
        max_retries: int = 3,
        backoff_seconds: float = 0.5,
    ) -> None:
        """
        Initializes the OpenSearch client.

        Args:
            base_url (str): The OpenSearch server base URL (e.g. https://host:9200).
            user (str): The username for authentication.
            password (str): The password for authentication.
            verify_tls (bool): Whether to verify TLS certificates.
        """
        self.base_url = base_url.rstrip("/")
        self.user = user
        self.password = password
        self.verify_tls = verify_tls
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self.client = httpx.Client(
            base_url=self.base_url,
            auth=(self.user, self.password),
            verify=self.verify_tls,
            timeout=timeout,
        )

    def _request(
        self,
        method: str,
        path: str,
        json_body: dict[str, Any] | None = None,
        run_id: str | None = None,
        case_id: str | None = None,
    ) -> tuple[dict[str, Any], str | None]:
        attempt = 0
        while True:
            attempt += 1
            response = self.client.request(method, path, json=json_body)
            if response.status_code in RETRY_STATUS_CODES and attempt <= self.max_retries:
                retry_after = response.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    delay = float(retry_after)
                else:
                    delay = self.backoff_seconds * (2 ** (attempt - 1))
                LOGGER.warning(
                    "OpenSearch retry",
                    extra={
                        "event": "retry",
                        "stage": "fetch",
                        "run_id": run_id,
                        "case_id": case_id,
                        "counts": {"attempt": attempt},
                        "duration_ms": int(delay * 1000),
                        "error": f"status={response.status_code}",
                    },
                )
                time.sleep(delay)
                continue

            response.raise_for_status()
            request_id = response.headers.get("x-request-id")
            return response.json(), request_id

    def create_pit(
        self,
        index_pattern: str,
        keep_alive: str = "1m",
        run_id: str | None = None,
        case_id: str | None = None,
    ) -> str:
        response, request_id = self._request(
            "POST",
            f"/{index_pattern}/_pit?keep_alive={keep_alive}",
            run_id=run_id,
            case_id=case_id,
        )
        pit_id = response.get("pit_id")
        if not pit_id:
            raise ValueError("PIT creation failed: missing pit_id")
        LOGGER.info(
            "Created PIT",
            extra={"event": "pit_created", "stage": "fetch", "run_id": run_id, "case_id": case_id},
        )
        return pit_id

    def search(
        self,
        pit_id: str,
        query_body: dict[str, Any],
        search_after: list | None = None,
        run_id: str | None = None,
        case_id: str | None = None,
    ) -> dict[str, Any]:
        body = dict(query_body)
        body["pit"] = {"id": pit_id, "keep_alive": "1m"}
        if search_after:
            body["search_after"] = search_after
        response, request_id = self._request(
            "POST",
            "/_search",
            json_body=body,
            run_id=run_id,
            case_id=case_id,
        )
        hits_count = len(response.get("hits", {}).get("hits", []))
        LOGGER.info(
            "Search completed",
            extra={
                "event": "search",
                "stage": "fetch",
                "run_id": run_id,
                "case_id": case_id,
                "counts": {"hits": hits_count},
            },
        )
        return response

    def delete_pit(
        self, pit_id: str, run_id: str | None = None, case_id: str | None = None
    ) -> None:
        _, request_id = self._request(
            "DELETE",
            "/_pit",
            json_body={"pit_id": pit_id},
            run_id=run_id,
            case_id=case_id,
        )
        LOGGER.info(
            "Deleted PIT",
            extra={"event": "pit_deleted", "stage": "fetch", "run_id": run_id, "case_id": case_id},
        )

    def close(self) -> None:
        """Closes the HTTP client."""
        self.client.close()


# TODO: Implement additional methods for other OpenSearch operations as needed.
