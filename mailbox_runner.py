"""Operator-only GitHub mailbox. No model, shell, filesystem, or oracle tool.

Encrypted requests and responses live on separate, pre-created branches. Tool
extensions must be registered in process with a validator and callable; the
request cannot name a module, executable, file, URL, or Python expression.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Callable
from mailbox_crypto import derive_key, generate_keypair, open_envelope, seal

MAX_REQUEST_BYTES = 16384
MAX_RESPONSE_BYTES = 65536
MAX_REQUESTS = 10000


class ProtocolError(ValueError):
    pass


def encode(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False,
                      separators=(",", ":"), sort_keys=True).encode("utf-8")


def bounded_json(value, depth=0):
    if depth > 12:
        raise ProtocolError("json_depth_exceeded")
    if value is None or type(value) in (bool, int):
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ProtocolError("nonfinite_number")
        return
    if type(value) is str:
        if len(value) > 8192:
            raise ProtocolError("string_too_large")
        return
    if type(value) is list:
        if len(value) > 256:
            raise ProtocolError("array_too_large")
        for item in value:
            bounded_json(item, depth + 1)
        return
    if type(value) is dict:
        if len(value) > 64 or any(type(k) is not str or len(k) > 128 for k in value):
            raise ProtocolError("object_too_large")
        for item in value.values():
            bounded_json(item, depth + 1)
        return
    raise ProtocolError("invalid_json_type")


def ping_arguments(arguments):
    if arguments != {}:
        raise ProtocolError("ping_arguments_must_be_empty")


def echo_arguments(arguments):
    if set(arguments) != {"value"}:
        raise ProtocolError("echo_requires_only_value")
    bounded_json(arguments["value"])
    if len(encode(arguments["value"])) > 8192:
        raise ProtocolError("echo_value_too_large")


@dataclass(frozen=True)
class ToolSpec:
    validate: Callable[[dict], None]
    invoke: Callable[[dict], object]


class Broker:
    def __init__(self, session, trace_path, extensions=None):
        self.session = str(uuid.UUID(session))
        if session != self.session:
            raise ValueError("session_must_be_canonical_uuid")
        self.trace_path = Path(trace_path)
        self.tools = {
            "ping": ToolSpec(ping_arguments, lambda _: {"pong": True}),
            "echo": ToolSpec(echo_arguments, lambda a: {"value": a["value"]}),
        }
        for name, spec in (extensions or {}).items():
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name) or name in self.tools:
                raise ValueError("invalid_extension_name")
            if not isinstance(spec, ToolSpec):
                raise ValueError("extension_requires_tool_spec")
            self.tools[name] = spec
        self.last_seq = 0
        self.cache = {}

    def trace(self, event, **fields):
        # Deliberately omit request arguments, responses, headers and exceptions.
        record = {"utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  "session": self.session, "event": event, **fields}
        with self.trace_path.open("ab") as stream:
            stream.write(encode(record) + b"\n")
            stream.flush()

    def process(self, request):
        digest = None
        seq = request.get("seq") if type(request) is dict else None
        if type(seq) is not int or seq < 1:
            seq = None
        response = {"session": self.session, "seq": seq, "ok": False,
                    "result": None, "error": None, "replayed": False}
        try:
            if type(request) is not dict or set(request) != {"session", "seq", "tool", "arguments"}:
                raise ProtocolError("invalid_request_schema")
            bounded_json(request)
            if len(encode(request)) > MAX_REQUEST_BYTES:
                raise ProtocolError("request_too_large")
            if request["session"] != self.session:
                raise ProtocolError("session_mismatch")
            if seq is None:
                raise ProtocolError("invalid_sequence")
            digest = hashlib.sha256(encode(request)).hexdigest()
            if seq in self.cache:
                old_digest, cached = self.cache[seq]
                if digest != old_digest:
                    raise ProtocolError("sequence_conflict")
                response = dict(cached, replayed=True)
                self.trace("replayed", seq=seq, request_sha256=digest)
                return response
            if seq != self.last_seq + 1:
                raise ProtocolError("sequence_not_next")
            if seq > MAX_REQUESTS:
                raise ProtocolError("request_limit_exceeded")
            tool = request["tool"]
            if type(tool) is not str or tool not in self.tools:
                raise ProtocolError("unsupported_tool")
            arguments = request["arguments"]
            if type(arguments) is not dict:
                raise ProtocolError("arguments_must_be_object")
            spec = self.tools[tool]
            spec.validate(arguments)
        except ProtocolError as error:
            response["error"] = str(error)
            # A rejected tool still completes a valid transport sequence. Never
            # reuse its ID for a different request and accept a stale response.
            if digest is not None and seq == self.last_seq + 1:
                self.last_seq = seq
                self.cache[seq] = (digest, dict(response))
            self.trace("rejected", seq=seq, code=response["error"])
            return response
        try:
            response["result"] = spec.invoke(arguments)
            bounded_json(response["result"])
            response["ok"] = True
            if len(encode(response)) > MAX_RESPONSE_BYTES:
                raise ProtocolError("response_too_large")
        except Exception:
            # Callback exception text may contain database URLs or credentials.
            response.update(ok=False, result=None, error="tool_execution_failed")
        self.last_seq = seq
        self.cache[seq] = (digest, dict(response))
        self.trace("executed", seq=seq, tool=tool, request_sha256=digest,
                   ok=response["ok"], code=response["error"])
        return response


class GitHubContents:
    def __init__(self, repo, token):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            raise ValueError("invalid_repository")
        if not token:
            raise ValueError("GITHUB_TOKEN_required")
        self.base = "https://api.github.com/repos/" + repo + "/contents/"
        self.token = token

    def call(self, method, filename, body=None, branch=None):
        if filename not in {"request.json", "response.json", "terminal.json",
                            "client_public_key.json", "server_public_key.json"}:
            raise ValueError("filename_not_allowed")
        url = self.base + filename
        if branch is not None:
            url += "?" + urllib.parse.urlencode({"ref": branch})
        request = urllib.request.Request(url, data=None if body is None else encode(body),
            method=method, headers={"Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json", "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "rca-operator-mailbox/1"})
        with urllib.request.urlopen(request, timeout=20) as result:
            raw = result.read(200000)
            if len(raw) >= 200000:
                raise ProtocolError("github_response_too_large")
            return json.loads(raw)

    def get(self, filename, branch):
        try:
            metadata = self.call("GET", filename, branch=branch)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None, None
            raise
        if metadata.get("encoding") != "base64" or metadata.get("type") != "file":
            raise ProtocolError("invalid_github_file")
        raw = base64.b64decode(metadata["content"])
        if len(raw) > 100000:
            raise ProtocolError("mailbox_file_too_large")
        return json.loads(raw), metadata["sha"]

    def put(self, filename, branch, value):
        content = base64.b64encode(encode(value)).decode("ascii")
        for attempt in range(5):
            _, sha = self.get(filename, branch)
            body = {"message": "Update operator mailbox " + filename,
                    "content": content, "branch": branch}
            if sha:
                body["sha"] = sha
            try:
                self.call("PUT", filename, body=body)
                return
            except urllib.error.HTTPError as error:
                if error.code not in (409, 422) or attempt == 4:
                    raise
                time.sleep(0.2 * (attempt + 1))


def run(broker, transport, request_branch, response_branch, max_seconds, poll_seconds, stop):
    started = time.monotonic()
    reason = "lifetime_elapsed"
    last_fingerprint = None
    key = None
    private, public = generate_keypair()
    broker.trace("started", max_seconds=max_seconds)
    try:
        while time.monotonic() - started < max_seconds and not stop.is_set():
            try:
                if key is None:
                    peer, _ = transport.get("client_public_key.json", request_branch)
                    if type(peer) is dict and set(peer) == {"session", "public_key"} and peer["session"] == broker.session:
                        candidate_key = derive_key(private, peer["public_key"], broker.session)
                        transport.put("server_public_key.json", response_branch,
                                      {"session": broker.session, "public_key": public})
                        key = candidate_key
                        broker.trace("encrypted_transport_ready")
                    else:
                        stop.wait(poll_seconds)
                        continue
                envelope, _ = transport.get("request.json", request_branch)
                if envelope is not None:
                    fingerprint = hashlib.sha256(encode(envelope)).hexdigest()
                    if fingerprint != last_fingerprint:
                        request = open_envelope(key, broker.session, envelope.get("seq"), "request", envelope)
                        if request.get("seq") != envelope["seq"]:
                            raise ProtocolError("inner_sequence_mismatch")
                        response = broker.process(request)
                        encrypted = seal(key, broker.session, envelope["seq"], "response", response)
                        transport.put("response.json", response_branch, encrypted)
                        last_fingerprint = fingerprint
            except Exception:
                # Retry transport errors without logging HTTP bodies or headers.
                broker.trace("transport_error")
            stop.wait(min(poll_seconds, max(0, max_seconds - (time.monotonic() - started))))
        if stop.is_set():
            reason = "operator_signal"
    finally:
        terminal = {"session": broker.session, "terminal": True, "reason": reason,
                    "last_seq": broker.last_seq, "remote_model_calls": 0}
        broker.trace("terminal", reason=reason, last_seq=broker.last_seq)
        transport.put("terminal.json", response_branch, terminal)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--request-branch", required=True)
    parser.add_argument("--response-branch", required=True)
    parser.add_argument("--session", required=True)
    parser.add_argument("--max-seconds", type=int, default=6 * 3600 - 120)
    parser.add_argument("--poll-seconds", type=float, default=10)
    parser.add_argument("--trace", type=Path, default=Path("mailbox-trace.jsonl"))
    args = parser.parse_args()
    if args.request_branch == args.response_branch:
        parser.error("request_and_response_branches_must_differ")
    if not 1 <= args.max_seconds <= 6 * 3600 or args.poll_seconds < 10:
        parser.error("invalid_lifetime_or_poll_interval")
    for branch in (args.request_branch, args.response_branch):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", branch) or ".." in branch:
            parser.error("invalid_branch")
    broker = Broker(args.session, args.trace)
    transport = GitHubContents(args.repo, os.environ.get("GITHUB_TOKEN", ""))
    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    try:
        run(broker, transport, args.request_branch, args.response_branch,
            args.max_seconds, args.poll_seconds, stop)
    except Exception:
        print("mailbox_terminal_write_failed")
        return 2
    print("mailbox_stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
