"""Pinned official Raw investigation session behind encrypted operator transport.

The worker sees only incident_context, execute_sql, describe_table,
query_metrics and submit_diagnosis. Payload framing is operator-side and is
not an investigation call. No credential, oracle, score or other arm is
returned to a worker. This file launches no model.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager, redirect_stdout, redirect_stderr
import hashlib
import importlib
import json
import os
from pathlib import Path
import signal
import secrets
import sys
import threading
import time
import traceback
from types import SimpleNamespace
import uuid

import actions_backend_preflight as preparation
import mailbox_runner as mailbox
from mailbox_runner import Broker, GitHubContents, ProtocolError, ToolSpec

SCORER_SHA256 = "8a47622f0492c93c57bc6b03ddfb67621bc71b925259982076645a2fa13966a6"
SEGMENT_BYTES = 4608
CHUNK_BYTES = 7 * SEGMENT_BYTES  # ~32KB, represented as seven <8192-char strings.
MAX_PAYLOAD_BYTES = 64 * 1024 * 1024


class PayloadVault:
    """Lossless, session-private framing; no path or arbitrary-data read API."""
    def __init__(self):
        self.outbound = {}
        self.inbound = {}

    def pack(self, value):
        raw = mailbox.encode(value)
        if len(raw) <= 7000:
            return {"payload_json": raw.decode("utf-8")}
        if len(raw) > MAX_PAYLOAD_BYTES:
            raise ProtocolError("transport_payload_capacity_exceeded_not_model_failure")
        token = str(uuid.uuid4())
        self.outbound[token] = raw
        return {"transfer_id": token, "total": (len(raw) + CHUNK_BYTES - 1) // CHUNK_BYTES,
                "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                "framing": "rca-lossless-json-chunks/1"}

    def fetch(self, arguments):
        if set(arguments) != {"transfer_id", "index"}:
            raise ProtocolError("invalid_chunk_fetch_schema")
        token, index = arguments["transfer_id"], arguments["index"]
        if token not in self.outbound or type(index) is not int:
            raise ProtocolError("unknown_transfer_or_index")
        raw = self.outbound[token]
        total = (len(raw) + CHUNK_BYTES - 1) // CHUNK_BYTES
        if not 0 <= index < total:
            raise ProtocolError("chunk_index_out_of_range")
        chunk = raw[index * CHUNK_BYTES:(index + 1) * CHUNK_BYTES]
        segments = [base64.b64encode(chunk[start:start + SEGMENT_BYTES]).decode("ascii")
                    for start in range(0, len(chunk), SEGMENT_BYTES)]
        return {"transfer_id": token, "index": index, "segments": segments,
                "sha256": hashlib.sha256(chunk).hexdigest()}

    def upload(self, arguments):
        expected = {"transfer_id", "index", "total", "bytes", "sha256", "segments"}
        if set(arguments) != expected:
            raise ProtocolError("invalid_chunk_upload_schema")
        token = arguments["transfer_id"]
        try:
            if str(uuid.UUID(token)) != token:
                raise ValueError()
        except Exception:
            raise ProtocolError("invalid_transfer_id") from None
        index, total, size = (arguments[k] for k in ("index", "total", "bytes"))
        if any(type(value) is not int for value in (index, total, size)):
            raise ProtocolError("invalid_chunk_metadata")
        if not 1 <= size <= MAX_PAYLOAD_BYTES or total != (size + CHUNK_BYTES - 1) // CHUNK_BYTES or not 0 <= index < total:
            raise ProtocolError("invalid_chunk_extent")
        digest = arguments["sha256"]
        if type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ProtocolError("invalid_payload_digest")
        segments = arguments["segments"]
        if type(segments) is not list or not 1 <= len(segments) <= 7:
            raise ProtocolError("invalid_chunk_segments")
        try:
            parts = [base64.b64decode(value, validate=True) for value in segments]
            if any(not 1 <= len(part) <= SEGMENT_BYTES for part in parts):
                raise ValueError()
            raw = b"".join(parts)
        except Exception:
            raise ProtocolError("invalid_chunk_encoding") from None
        expected_size = min(CHUNK_BYTES, size - index * CHUNK_BYTES)
        if len(raw) != expected_size:
            raise ProtocolError("chunk_size_mismatch")
        slot = self.inbound.setdefault(token, {"total": total, "bytes": size,
                                              "sha256": digest, "chunks": {}})
        if any(slot[key] != arguments[key] for key in ("total", "bytes", "sha256")):
            raise ProtocolError("upload_metadata_conflict")
        old = slot["chunks"].get(index)
        if old is not None and old != raw:
            raise ProtocolError("upload_chunk_conflict")
        slot["chunks"][index] = raw
        complete = len(slot["chunks"]) == total
        if complete:
            payload = b"".join(slot["chunks"][i] for i in range(total))
            if hashlib.sha256(payload).hexdigest() != digest:
                raise ProtocolError("uploaded_payload_hash_mismatch")
        return {"transfer_id": token, "index": index, "complete": complete}

    def uploaded(self, token):
        slot = self.inbound.get(token)
        if slot is None or len(slot["chunks"]) != slot["total"]:
            raise ProtocolError("upload_incomplete")
        raw = b"".join(slot["chunks"][i] for i in range(slot["total"]))
        if len(raw) != slot["bytes"] or hashlib.sha256(raw).hexdigest() != slot["sha256"]:
            raise ProtocolError("uploaded_payload_integrity_failed")
        return json.loads(raw)


def unchanged_causal_score(scorer, native_run, spec, model, effort, max_calls):
    """Use the exact scorer on truthful native fields, without API projection.

The scorer is duck-typed and computes causal endpoints independently from
its strict API-runner completion contract. That contract correctly fails;
its success/completion/efficiency fields are not native-pilot endpoints.
"""
    result = scorer.evaluate_transfer_run(native_run, spec,
        expected_model=model, expected_transport=None,
        expected_reasoning_effort=effort, expected_max_output_tokens=16384,
        max_tool_calls=max_calls)
    full = result.model_dump(mode="json")
    primary = {key: full[key] for key in (
        "diagnosis_correct", "causal_locus_match", "causal_scope_match",
        "fault_category_match", "mechanism_code_match", "causal_locus_evidence_match",
        "mechanism_evidence_match", "required_evidence_covered", "citations_execution_valid",
        "grounding_not_estimable_reason", "evidence_audit_failure_reasons")}
    return {"primary_causal_endpoints": primary,
        "official_scorer_unchanged": True, "official_api_runner_contract_match": False,
        "official_completion_fields_applicable": False,
        "native_execution_reliability": (native_run.error is None
            and not native_run.tool_budget_exhausted and len(native_run.tool_calls) <= max_calls
            and not any(getattr(item, "reason_code", None) == "invalid"
                        for item in native_run.rejected_tool_calls)),
        "unmodified_scorer_output": full}


class RawMailboxBridge:
    def __init__(self, prepared, protocol, operator_root, model, effort, stop,
                 *, agent=None, contracts=None, scorer=None, gateway_factory=None):
        self.agent = agent or importlib.import_module("agent_rca_bench.agent")
        self.contracts = contracts or importlib.import_module("agent_rca_bench.contracts")
        self.scorer = scorer or importlib.import_module("agent_rca_bench.transfer_scorer")
        if gateway_factory is None:
            gateway_factory = importlib.import_module("agent_rca_bench.greptimedb.visibility").QueryGateway
        self.gateway_factory = gateway_factory
        self.prepared, self.protocol, self.root = prepared, protocol, Path(operator_root)
        self.model, self.effort, self.stop = model, effort, stop
        self.visibility = self.contracts.Visibility.RAW
        self.tools = self.agent._investigation_tools(self.visibility,
            prepared.case.input.fault_taxonomy, prepared.semantic_coverage, promql=True)
        self.session = self.agent.InvestigationSession(
            gateway_factory(prepared.client, self.visibility), prepared.case.input, self.visibility,
            max_tool_calls=protocol.max_tool_calls, semantic_coverage=prepared.semantic_coverage,
            investigation_tools=self.tools)
        self.vault = PayloadVault()
        self.started = time.monotonic()
        self.closed = False
        self.diagnosis = None
        self.run_id = "native-" + str(uuid.uuid4())
        self.operator_nonce = secrets.token_urlsafe(32)
        self.turns = None  # Actual Codex JSONL metering must supply this independently.

    def incident_context(self, arguments):
        if arguments:
            raise ProtocolError("incident_context_arguments_must_be_empty")
        neutral_input = self.prepared.case.input.model_copy(update={"case_token": "incident"})
        worker_input = {key: value for key, value in neutral_input.model_dump(mode="json").items()
                        if key in {"case_token", "database", "time_start", "time_end",
                                   "alert_time", "alert_text", "fault_taxonomy"}}
        return self.vault.pack({"case_input": worker_input,
            "system_prompt": self.agent._system_prompt(self.visibility),
            "user_prompt": self.agent._incident_prompt(neutral_input,
                self.protocol.max_tool_calls, self.visibility),
            "investigation_tools": self.tools,
            "output_tool": self.agent._submit_tool(self.prepared.case.input.fault_taxonomy),
            "max_tool_calls": self.protocol.max_tool_calls,
            "remaining": self.session.remaining,
            "native_interface_note": "submit_diagnosis validates a draft without freezing or scoring. "
                "The host freezes only the accepted final standalone report after the requested "
                "diagnostic passes. All worker tools share the same official 48-call evidence ledger."})

    def operator_contract(self, arguments):
        if arguments:
            raise ProtocolError("operator_contract_arguments_must_be_empty")
        return self.vault.pack({"operator_nonce": self.operator_nonce,
            "actual_database": self.prepared.case.input.database,
            "run_id": self.run_id,
            "warning": "operator-only; never put this payload or nonce into a worker workspace"})

    def operator_preflight(self, arguments):
        if set(arguments) != {"operator_nonce"} or not secrets.compare_digest(
                str(arguments.get("operator_nonce", "")), self.operator_nonce):
            raise ProtocolError("operator_preflight_authorization_failed")
        if self.session.tool_calls_requested != 0 or self.closed:
            raise ProtocolError("operator_preflight_requires_pristine_worker_ledger")
        before = (len(self.session.tool_calls), self.session.remaining)
        probe = self.agent.InvestigationSession(
            self.gateway_factory(self.prepared.client, self.visibility),
            self.prepared.case.input, self.visibility,
            max_tool_calls=self.protocol.max_tool_calls,
            semantic_coverage=self.prepared.semantic_coverage, investigation_tools=self.tools)
        database = self.prepared.case.input.database
        if not all(character.isalnum() or character == "_" for character in database):
            raise ProtocolError("fixed_probe_database_identifier_invalid")
        queries = ["SELECT 1 AS preflight_ok",
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = '" + database + "' ORDER BY table_name"]
        invocations = []
        for query in queries:
            value = probe.invoke("execute_sql", {"query": query, "max_rows": 1000})
            invocations.append({"content": value.content, "is_error": value.is_error,
                                "remaining": value.remaining})
        after = (len(self.session.tool_calls), self.session.remaining)
        if before != after or self.session.tool_calls_requested != 0:
            raise ProtocolError("operator_probe_contaminated_worker_ledger")
        result = {"operator_only": True, "official_invocations": invocations,
            "main_tool_calls_before": before[0], "main_tool_calls_after": after[0],
            "main_remaining_before": before[1], "main_remaining_after": after[1],
            "main_citations_count": len(self.session.tool_calls),
            "probe_tool_calls": [trace.model_dump(mode="json") for trace in probe.tool_calls],
            "all_probes_succeeded": all(not invocation["is_error"] for invocation in invocations)}
        preparation.write_json(self.root / "operator_preflight_trace.json", result)
        return self.vault.pack(result)

    def invoke(self, name, arguments):
        if self.closed:
            return self.vault.pack({"content": "investigation already frozen", "is_error": True,
                                    "remaining": self.session.remaining})
        invocation = self.session.invoke(name, arguments)
        self.persist_native()
        return self.vault.pack({"content": invocation.content, "is_error": invocation.is_error,
                                "remaining": invocation.remaining})

    def submit(self, arguments):
        if self.closed:
            return self.vault.pack({"accepted": False, "error": "investigation already frozen"})
        try:
            output = self.agent._validate_diagnosis_output(arguments)
            self.session.validate_diagnosis_citations(output)
        except Exception as error:
            # Encrypted worker-facing validation only; never plaintext stdout.
            return self.vault.pack({"accepted": False, "error": str(error),
                                   "remaining": self.session.remaining})
        return self.vault.pack({"accepted": True, "frozen": False,
            "validation_only": True, "remaining": self.session.remaining})

    def finalize(self, arguments):
        if set(arguments) != {"operator_nonce", "diagnosis"} or not secrets.compare_digest(
                str(arguments.get("operator_nonce", "")), self.operator_nonce):
            raise ProtocolError("operator_finalization_authorization_failed")
        if self.closed:
            return self.vault.pack({"accepted": False, "error": "investigation already frozen"})
        output = self.agent._validate_diagnosis_output(arguments["diagnosis"])
        self.session.validate_diagnosis_citations(output)
        self.diagnosis = self.contracts.Diagnosis.model_validate(output)
        preparation.write_json(self.root / "frozen_diagnosis.json", output)
        self.closed = True
        native = self.native_run()
        evaluation = unchanged_causal_score(self.scorer, native, self.prepared.spec,
            self.model, self.effort, self.protocol.max_tool_calls)
        preparation.write_json(self.root / "evaluation.json", evaluation)
        self.persist_native()
        # Do not stop the mailbox here: large final acknowledgement chunks must
        # remain fetchable. The operator lifetime/termination closes the service.
        return self.vault.pack({"accepted": True, "frozen": True,
                                "remaining": self.session.remaining, "evaluation": evaluation})

    def submit_transfer(self, arguments):
        if set(arguments) != {"transfer_id"}:
            raise ProtocolError("invalid_submit_transfer_schema")
        return self.submit(self.vault.uploaded(arguments["transfer_id"]))

    def invoke_transfer(self, arguments):
        if set(arguments) != {"transfer_id"}:
            raise ProtocolError("invalid_invoke_transfer_schema")
        payload = self.vault.uploaded(arguments["transfer_id"])
        if type(payload) is not dict or set(payload) != {"tool", "arguments"} or type(payload["arguments"]) is not dict:
            raise ProtocolError("invalid_uploaded_invocation_schema")
        if payload["tool"] == "submit_diagnosis":
            return self.submit(payload["arguments"])
        if payload["tool"] not in {tool["name"] for tool in self.tools}:
            raise ProtocolError("uploaded_tool_not_in_official_allowlist")
        return self.invoke(payload["tool"], payload["arguments"])

    def finalize_transfer(self, arguments):
        if set(arguments) != {"operator_nonce", "transfer_id"}:
            raise ProtocolError("invalid_finalize_transfer_schema")
        return self.finalize({"operator_nonce": arguments["operator_nonce"],
                              "diagnosis": self.vault.uploaded(arguments["transfer_id"])})

    def native_run(self):
        return SimpleNamespace(run_id=self.run_id,
            visibility=self.visibility, model=self.model, runner="codex-cli-subscription",
            api_transport=None, reasoning_effort=self.effort, max_output_tokens=None,
            diagnosis=self.diagnosis, error=None if self.closed else "native_investigation_incomplete",
            tool_calls=self.session.tool_calls, rejected_tool_calls=self.session.rejected_tool_calls,
            tool_calls_requested=self.session.tool_calls_requested,
            tool_budget_exhausted=self.session.tool_budget_exhausted,
            usage=None, elapsed_seconds=time.monotonic() - self.started, responses=None)

    def persist_native(self):
        native = self.native_run()
        raw = {key: value for key, value in vars(native).items()
               if key not in {"diagnosis", "tool_calls", "rejected_tool_calls", "visibility"}}
        raw.update(visibility=self.visibility.value,
            diagnosis=None if self.diagnosis is None else self.diagnosis.model_dump(mode="json"),
            tool_calls=[item.model_dump(mode="json") for item in self.session.tool_calls],
            rejected_tool_calls=[item.model_dump(mode="json") for item in self.session.rejected_tool_calls],
            max_turns_adaptation={"official_api_max_turns": self.protocol.max_turns,
                "native_jsonl_turn_count": self.turns, "enforced": False},
            token_usage_measured=False, transport="encrypted-github-mailbox",
            elapsed_measurement="backend session wall time including host and transport waits; "
                                "actual native model time requires local JSONL metering",
            official_api_runner_contract_match=False)
        preparation.write_json(self.root / "native_run.json", raw)

    def extensions(self):
        validate = lambda _: None  # Official invoke retains its own error/budget behavior.
        result = {tool["name"]: ToolSpec(validate,
                  lambda arguments, name=tool["name"]: self.invoke(name, arguments)) for tool in self.tools}
        result.update(incident_context=ToolSpec(validate, self.incident_context),
            get_worker_contract=ToolSpec(validate, self.incident_context),
            get_operator_contract=ToolSpec(validate, self.operator_contract),
            operator_preflight=ToolSpec(validate, self.operator_preflight),
            submit_diagnosis=ToolSpec(validate, self.submit),
            fetch_payload_chunk=ToolSpec(validate, self.vault.fetch),
            upload_payload_chunk=ToolSpec(validate, self.vault.upload),
            submit_diagnosis_transfer=ToolSpec(validate, self.submit_transfer),
            invoke_official_transfer=ToolSpec(validate, self.invoke_transfer),
            operator_finalize=ToolSpec(validate, self.finalize),
            operator_finalize_transfer=ToolSpec(validate, self.finalize_transfer))
        return result


@contextmanager
def live_prepared(benchmark_repo, archive, root):
    fixture = preparation.verify_bindings(benchmark_repo)
    if preparation.sha256_file(benchmark_repo / "src/agent_rca_bench/transfer_scorer.py") != SCORER_SHA256:
        raise ValueError("official_scorer_source_binding_failed")
    sys.path.insert(0, str(benchmark_repo / "src"))
    protocol_module = importlib.import_module("agent_rca_bench.transfer_protocol")
    formal = importlib.import_module("agent_rca_bench.transfer_formal")
    server = importlib.import_module("agent_rca_bench.greptimedb.server")
    original, cohort = protocol_module.load_transfer_protocol(fixture)
    derived = original.model_copy(update={"greptimedb_build_profile": "debug"})
    spec = next(spec for spec in cohort.selected_cases if spec.opaque_case_id == preparation.SELECTED[0])
    greptime_repo = root / "greptimedb"
    with (root / "checkout.log").open("w") as log:
        preparation.checkout_greptime(greptime_repo, log)
    binary_hash = preparation.extract_verified_binary(archive, greptime_repo / "target/debug/greptime")
    observed = server.inspect_checkout(greptime_repo, build_profile="debug")
    if observed["head"] != preparation.GREPTIME_SHA or not preparation.version_matches_revision(observed["binary_version"]):
        raise ValueError("binary_version_binding_failed")
    preparation.write_json(root / "native_runtime_registration.json", {
        "benchmark_revision": preparation.BENCHMARK_SHA,
        "greptimedb_revision": preparation.GREPTIME_SHA, "binary_sha256": binary_hash,
        "tar_sha256": preparation.TAR_SHA256, "build_profile": "debug",
        "extra_build_features": ["pg_kvbackend", "mysql_kvbackend", "vector_index"],
        "official_release_reproduction": False, "actual_runner": "codex-cli-subscription",
        "api_transport": None, "scorer_unchanged_sha256": SCORER_SHA256,
        "official_completion_fields_applicable": False,
        "max_turns_native_metering_required": True, "derived_protocol": derived.model_dump(mode="json")})
    cache = root / "source_cache/openrca2"
    config = formal.TransferEnvironmentConfig(cache_dir=cache, manifest_path=cache / "manifest.jsonl",
        greptimedb_repo=greptime_repo, run_dir=root / "live_run",
        database=spec.opaque_case_id.replace("-", "_"), node_cache_dir=root / "source_cache/rca100")
    with formal.prepare_transfer_environment(derived, spec, config) as prepared:
        preparation.write_json(root / "live_operator_audit.json", prepared.source_audit)
        yield prepared, derived
    preparation.write_json(root / "live_operator_audit.json", prepared.source_audit)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark-repo", type=Path, required=True)
    parser.add_argument("--bins-tar", type=Path, required=True)
    parser.add_argument("--operator-root", type=Path, required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--request-branch", required=True)
    parser.add_argument("--response-branch", required=True)
    parser.add_argument("--session", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--effort", choices=["high"], default="high")
    parser.add_argument("--max-seconds", type=int, default=7200)
    args = parser.parse_args()
    root, runner_temp = args.operator_root.resolve(), Path(os.environ["RUNNER_TEMP"]).resolve()
    if root.exists() or root == runner_temp or not root.is_relative_to(runner_temp):
        parser.error("operator_root_must_be_new_inside_RUNNER_TEMP")
    if not 1 <= args.max_seconds <= 20000 or args.request_branch == args.response_branch:
        parser.error("invalid_lifetime_or_branches")
    root.mkdir(parents=True, mode=0o700)
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    # Large input framing has seven safe <=8192-char strings. Its encrypted
    # envelope stays under the unchanged crypto 64KB limit. Ordinary official
    # tool output is never shortened to make it fit a transport frame.
    mailbox.MAX_REQUEST_BYTES = 65536
    with (root / "operator_output.log").open("w") as log:
        try:
            with redirect_stdout(log), redirect_stderr(log):
                with live_prepared(args.benchmark_repo.resolve(), args.bins_tar.resolve(), root) as (prepared, protocol):
                    bridge = RawMailboxBridge(prepared, protocol, root, args.model, args.effort, stop)
                    bridge.persist_native()
                    broker = Broker(args.session, root / "mailbox-trace.jsonl", bridge.extensions())
                    transport = GitHubContents(args.repo, os.environ.get("GITHUB_TOKEN", ""))
                    try:
                        mailbox.run(broker, transport, args.request_branch, args.response_branch,
                                    args.max_seconds, 10, stop)
                    finally:
                        bridge.persist_native()
        except Exception:
            traceback.print_exc(file=log)
            print("persistent_backend_failed_unscored_or_incomplete")
            return 1
    print("persistent_backend_stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
