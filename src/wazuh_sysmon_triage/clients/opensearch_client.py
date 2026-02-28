# File: /wazuh-sysmon-triage/wazuh-sysmon-triage/src/wazuh_sysmon_triage/clients/opensearch_client.py

from __future__ import annotations

import logging
import re
import time
from typing import Any

import httpx

LOGGER = logging.getLogger(__name__)


RETRY_STATUS_CODES = {429, 502, 503}
DEFAULT_TIMEOUT = httpx.Timeout(30.0, connect=10.0)
_INDEX_PATTERN_RE = re.compile(r"^[a-zA-Z0-9_.\-*,]+$")


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
        self.verify_tls = verify_tls
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self.client = httpx.Client(
            base_url=self.base_url,
            auth=(self.user, password),
            verify=self.verify_tls,
            timeout=timeout,
        )
        # Password is no longer stored as an instance attribute;
        # httpx.Client holds auth internally.

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
            try:
                response = self.client.request(method, path, json=json_body)
            except httpx.TransportError as exc:
                if attempt <= self.max_retries:
                    delay = self.backoff_seconds * (2 ** (attempt - 1))
                    LOGGER.warning(
                        "OpenSearch transport retry",
                        extra={
                            "event": "retry_transport",
                            "stage": "fetch",
                            "run_id": run_id,
                            "case_id": case_id,
                            "counts": {"attempt": attempt},
                            "duration_ms": int(delay * 1000),
                            "error": str(exc),
                        },
                    )
                    time.sleep(delay)
                    continue
                raise ValueError(
                    "OpenSearch request failed after retries due to transport errors "
                    f"against {self.base_url}: {exc}. "
                    "Check host/port reachability, SSH tunnel, and TLS settings (use --no-verify-tls in lab)."
                ) from exc

            # Friendly diagnostics when users accidentally point at OpenSearch Dashboards
            # (often exposed on :443) instead of the OpenSearch Indexer HTTP API (often :9200).
            if response.status_code in {301, 302, 303, 307, 308}:
                location = response.headers.get("location") or ""
                if "/app/login" in location:
                    raise ValueError(
                        "Endpoint looks like OpenSearch Dashboards (redirects to /app/login). "
                        "Point --host (or WAZUH_OS_HOST) to the OpenSearch Indexer HTTP API instead "
                        "(commonly https://<indexer>:9200)."
                    )

            if response.status_code >= 400:
                try:
                    body = response.json()
                except Exception:
                    body = None

                if isinstance(body, dict) and {"statusCode", "error", "message"}.issubset(
                    body.keys()
                ):
                    # This error shape is typical of Dashboards/proxy handlers.
                    if (
                        body.get("statusCode") == 404
                        and str(body.get("message", "")).lower() == "not found"
                    ):
                        raise ValueError(
                            "Received 404 Not Found from the server. This often means --host points to "
                            "Wazuh/OpenSearch Dashboards (web UI) rather than the OpenSearch Indexer API. "
                            "Try https://<indexer>:9200 (or open port 9200 / fix firewall)."
                        )

            # Some Wazuh indexer deployments do not expose the PIT API.
            # OpenSearch/Elasticsearch typically return a 400 with a "no handler found" message.
            if (
                response.status_code == 400
                and "_pit" in path
                and "no handler found for uri" in response.text
            ):
                raise ValueError(
                    "PIT API not supported by this OpenSearch endpoint. "
                    "The triage tool will need to fall back to non-PIT pagination (search_after without PIT) "
                    "or you must upgrade/enable PIT support on the indexer."
                )
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

    @staticmethod
    def _validate_index_pattern(index_pattern: str) -> str:
        """Validate index_pattern to prevent path traversal in URL construction."""
        if not _INDEX_PATTERN_RE.match(index_pattern):
            raise ValueError(
                f"Invalid index_pattern '{index_pattern}': "
                "must contain only alphanumeric characters, dots, hyphens, underscores, asterisks, and commas."
            )
        if ".." in index_pattern:
            raise ValueError(
                f"Invalid index_pattern '{index_pattern}': path traversal sequences are not allowed."
            )
        return index_pattern

    def search_index(
        self,
        index_pattern: str,
        query_body: dict[str, Any],
        search_after: list | None = None,
        run_id: str | None = None,
        case_id: str | None = None,
    ) -> dict[str, Any]:
        self._validate_index_pattern(index_pattern)
        body = dict(query_body)
        if search_after:
            body["search_after"] = search_after
        response, request_id = self._request(
            "POST",
            f"/{index_pattern}/_search",
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
