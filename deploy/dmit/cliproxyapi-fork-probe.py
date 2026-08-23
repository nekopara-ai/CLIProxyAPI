#!/usr/bin/env python3
"""Secret-safe local health and Responses probes for the DMIT CPA service."""

from __future__ import annotations

import argparse
import http.client
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import yaml


MARKER = "CPA_AUTO_UPDATE_OK"


class ProbeError(RuntimeError):
    pass


def load_runtime(config_path: Path) -> tuple[int, str]:
    with config_path.open("r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}

    port = config.get("port")
    api_keys = config.get("api-keys") or []
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ProbeError("invalid_port")
    if not isinstance(api_keys, list):
        raise ProbeError("invalid_api_keys")
    for value in api_keys:
        if isinstance(value, str) and value.strip():
            return port, value.strip()
    raise ProbeError("missing_api_key")


def request(
    port: int,
    api_key: str,
    method: str,
    path: str,
    body: bytes | None,
    timeout: float,
) -> http.client.HTTPResponse:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    headers = {"Authorization": f"Bearer {api_key}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    response._cpa_connection = connection  # type: ignore[attr-defined]
    return response


def close_response(response: http.client.HTTPResponse) -> None:
    connection = getattr(response, "_cpa_connection", None)
    try:
        response.close()
    finally:
        if connection is not None:
            connection.close()


def probe_models(port: int, api_key: str) -> list[str]:
    response = request(port, api_key, "GET", "/v1/models", None, 15)
    try:
        payload = response.read(2 * 1024 * 1024)
        if response.status != 200:
            raise ProbeError(f"models_http_{response.status}")
        parsed = json.loads(payload)
    finally:
        close_response(response)

    entries = parsed.get("data") if isinstance(parsed, dict) else None
    if not isinstance(entries, list) or not entries:
        raise ProbeError("empty_model_catalog")
    models = [entry.get("id") for entry in entries if isinstance(entry, dict)]
    models = [model for model in models if isinstance(model, str) and model]
    if not models:
        raise ProbeError("missing_model_ids")
    return models


def select_model(models: list[str]) -> str:
    requested = os.environ.get("CPA_UPDATE_PROBE_MODEL", "gpt-5.6-sol")
    if requested in models:
        return requested
    for model in models:
        if model.startswith("gpt-"):
            return model
    return models[0]


def response_payload(model: str, stream: bool) -> bytes:
    return json.dumps(
        {
            "model": model,
            "input": f"Reply with exactly {MARKER}",
            "stream": stream,
            "max_output_tokens": 32,
        },
        separators=(",", ":"),
    ).encode("utf-8")


def probe_nonstream(port: int, api_key: str, model: str) -> None:
    response = request(
        port,
        api_key,
        "POST",
        "/v1/responses",
        response_payload(model, False),
        180,
    )
    try:
        payload = response.read(4 * 1024 * 1024)
        if response.status != 200:
            raise ProbeError(f"nonstream_http_{response.status}")
        parsed: Any = json.loads(payload)
    finally:
        close_response(response)
    if MARKER not in json.dumps(parsed, ensure_ascii=False):
        raise ProbeError("nonstream_marker_missing")


def probe_stream(port: int, api_key: str, model: str) -> None:
    response = request(
        port,
        api_key,
        "POST",
        "/v1/responses",
        response_payload(model, True),
        180,
    )
    completed = False
    total = 0
    text_deltas: list[str] = []
    marker_in_event = False
    try:
        if response.status != 200:
            response.read(1024)
            raise ProbeError(f"stream_http_{response.status}")
        while True:
            line = response.readline(1024 * 1024)
            if not line:
                break
            total += len(line)
            if total > 8 * 1024 * 1024:
                raise ProbeError("stream_too_large")
            decoded = line.decode("utf-8", errors="replace")
            if decoded.strip() == "event: response.completed":
                completed = True
            if decoded.startswith("data:"):
                try:
                    event = json.loads(decoded[5:].strip())
                except json.JSONDecodeError:
                    continue
                if isinstance(event, dict):
                    event_type = event.get("type")
                    if event_type == "response.completed":
                        completed = True
                    delta = event.get("delta")
                    if event_type == "response.output_text.delta" and isinstance(
                        delta, str
                    ):
                        text_deltas.append(delta)
                    marker_in_event = marker_in_event or MARKER in json.dumps(
                        event, ensure_ascii=False
                    )
    finally:
        close_response(response)
    if not completed:
        raise ProbeError("stream_completion_missing")
    if not marker_in_event and MARKER not in "".join(text_deltas):
        raise ProbeError("stream_marker_missing")


def retry_probe(name: str, attempts: int, callback: Any) -> None:
    last_error = "unknown"
    for attempt in range(1, attempts + 1):
        try:
            callback()
            return
        except (ProbeError, OSError, json.JSONDecodeError) as exc:
            last_error = str(exc) if isinstance(exc, ProbeError) else type(exc).__name__
            if attempt < attempts:
                time.sleep(3 * attempt)
    raise ProbeError(f"{name}_failed:{last_error}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("models", "e2e", "all"))
    parser.add_argument("--config", default="/root/cliproxyapi/config.yaml")
    parser.add_argument("--attempts", type=int, default=2)
    args = parser.parse_args()

    if not 1 <= args.attempts <= 5:
        parser.error("--attempts must be between 1 and 5")

    started = time.monotonic()
    try:
        port, api_key = load_runtime(Path(args.config))
        models = probe_models(port, api_key)
        model = select_model(models)
        if args.mode in ("e2e", "all"):
            retry_probe(
                "nonstream",
                args.attempts,
                lambda: probe_nonstream(port, api_key, model),
            )
            retry_probe(
                "stream",
                args.attempts,
                lambda: probe_stream(port, api_key, model),
            )
        result = {
            "ok": True,
            "mode": args.mode,
            "model_count": len(models),
            "probe_model": model,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
        }
        print(json.dumps(result, separators=(",", ":")))
        return 0
    except Exception as exc:  # Keep output secret-safe and machine-readable.
        error = str(exc) if isinstance(exc, ProbeError) else type(exc).__name__
        result = {
            "ok": False,
            "mode": args.mode,
            "error": str(error)[:160],
            "elapsed_ms": round((time.monotonic() - started) * 1000),
        }
        print(json.dumps(result, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
