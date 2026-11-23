"""Check the health and locally installed models of a loopback Ollama server."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from http.client import HTTPException
from urllib.error import URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener
from urllib.parse import urlsplit

MAX_RESPONSE_BYTES = 1_000_000


def check(url: str, model: str | None = None) -> tuple[bool, str]:
    try:
        parsed = urlsplit(url)
        if (parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password or
                parsed.query or parsed.fragment or parsed.path not in {"", "/"}):
            return False, "Only a plain http:// loopback base URL is allowed."
        try:
            port = parsed.port
            loopback = parsed.hostname.casefold() == "localhost" or ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            return False, "The Ollama URL contains an invalid loopback address or port."
        if not loopback:
            return False, "Only an http:// loopback Ollama URL is allowed."
    except (TypeError, ValueError):
        return False, "Invalid Ollama URL."
    host = "127.0.0.1" if parsed.hostname.casefold() == "localhost" else parsed.hostname
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    endpoint = f"http://{netloc}/api/tags"
    try:
        opener = build_opener(ProxyHandler({}), _NoRedirect())
        with opener.open(endpoint, timeout=3) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            return False, "Ollama response exceeded the configured byte limit."
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict) or not isinstance(payload.get("models", []), list):
            return False, "Ollama returned an unexpected model-list response."
        if any(not isinstance(entry, dict) or not isinstance(entry.get("name", ""), str)
               for entry in payload.get("models", [])):
            return False, "Ollama returned an unexpected model entry."
    except (OSError, HTTPException, URLError, TimeoutError, json.JSONDecodeError,
            UnicodeDecodeError, RecursionError, TypeError) as exc:
        return False, f"Ollama is unavailable at {parsed.netloc}: {exc}"
    models = [entry.get("name", "") for entry in payload.get("models", [])]
    lines = [f"Ollama is reachable at {parsed.netloc}.", f"Installed models: {', '.join(models) if models else '(none)'}"]
    if model:
        found = any(name == model or name.startswith(model + ":") for name in models)
        lines.append(f"Model {model!r}: {'available' if found else 'not installed'}.")
        return found, "\n".join(lines)
    return True, "\n".join(lines)


class _NoRedirect(HTTPRedirectHandler):
    """Prevent a local service response from sending the checker elsewhere."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:11434")
    parser.add_argument("--model")
    args = parser.parse_args(argv)
    reachable, message = check(args.url, args.model)
    print(message)
    return 0 if reachable else 1


if __name__ == "__main__":
    sys.exit(main())
