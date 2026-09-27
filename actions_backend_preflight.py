"""Selected-case, operator-only derived-debug backend preflight.

Run with the pinned benchmark's Python 3.11 environment. Raw audit reports,
service logs, source data and failures stay under RUNNER_TEMP. Never upload
that directory publicly. Only the explicitly sanitized public receipt may
be published. This adapter starts no agent and invokes no model.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import traceback
import uuid

BENCHMARK_SHA = "fdfbca65c87c36c6b06bddfa6d611544f13bfa34"
GREPTIME_SHA = "15317a131bc63a680d3571e5f681bee4acc86228"
TAR_SHA256 = "46d2fbf6e7f3c873c57f43dd6bb4f358bbf1dcde6e9b782d8c9e987344344f6c"
BINARY_BYTES = 897813896
PROTOCOL_SHA256 = "398634ac21f576bf4fdc765162a06fad5cc49e7917676e42c423c1f2efece19b"
SELECTED = ("semantic-rca-transfer-011", "semantic-rca-transfer-006")
SOURCE_BINDINGS = {
    "src/agent_rca_bench/transfer_formal.py": "a39a1cd2052c026afcd549b3303680e889a49e6173c7fe6edd43c24ac836e53a",
    "src/agent_rca_bench/greptimedb/server.py": "1a74f9ffc6496490a9bb824c91256a6c889538a70a40bfe9dc0c59366b0dfcca",
    "src/agent_rca_bench/split_stack.py": "e9e746804046c4f87fcde575d65c3241c16e9682b080e9d5c57089fad3f050e4",
}


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, default=str) + "\n")


def verify_bindings(benchmark_repo):
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=benchmark_repo, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"],
                                    cwd=benchmark_repo, text=True).strip()
    if head != BENCHMARK_SHA or dirty:
        raise ValueError("benchmark_checkout_binding_failed")
    for relative, expected in SOURCE_BINDINGS.items():
        if sha256_file(benchmark_repo / relative) != expected:
            raise ValueError("benchmark_source_binding_failed")
    fixture = benchmark_repo / "fixtures/reference/transfer-v34-protocol.json"
    if sha256_file(fixture) != PROTOCOL_SHA256:
        raise ValueError("protocol_fixture_binding_failed")
    return fixture


def extract_verified_binary(archive, destination, *, expected_hash=TAR_SHA256,
                            expected_bytes=BINARY_BYTES):
    if sha256_file(archive) != expected_hash:
        raise ValueError("upstream_archive_hash_mismatch")
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        seen = set()
        binary = None
        for member in members:
            path = PurePosixPath(member.name)
            if member.name not in {"bins", "bins/greptime", "bins/sqlness-runner"}:
                raise ValueError("unexpected_archive_member")
            if path.is_absolute() or ".." in path.parts or member.name in seen:
                raise ValueError("unsafe_archive_member")
            seen.add(member.name)
            if member.name == "bins":
                if not member.isdir():
                    raise ValueError("invalid_archive_directory")
            elif not member.isfile() or member.issym() or member.islnk():
                raise ValueError("archive_link_or_special_file_rejected")
            if member.name == "bins/greptime":
                binary = member
        if binary is None or binary.size != expected_bytes:
            raise ValueError("binary_member_binding_failed")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise ValueError("binary_destination_already_exists")
        stream = tar.extractfile(binary)
        if stream is None:
            raise ValueError("binary_member_unreadable")
        with stream, destination.open("xb") as output:
            shutil.copyfileobj(stream, output, length=1024 * 1024)
        if destination.stat().st_size != expected_bytes:
            raise ValueError("extracted_binary_size_mismatch")
        destination.chmod(0o755)
    return sha256_file(destination)


def checkout_greptime(destination, log):
    if destination.exists():
        raise ValueError("greptime_checkout_destination_already_exists")
    destination.mkdir()
    for argv in (["git", "init"], ["git", "remote", "add", "origin",
                 "https://github.com/GreptimeTeam/greptimedb.git"],
                 ["git", "fetch", "--depth=1", "origin", GREPTIME_SHA],
                 ["git", "checkout", "--detach", "FETCH_HEAD"]):
        subprocess.run(argv, cwd=destination, stdout=log, stderr=log, check=True)


def version_matches_revision(version):
    # Upstream's --version may render a short Git hash. Exact full SHA is also
    # bound by upstream artifact run provenance, tar hash and clean checkout.
    tokens = re.findall(r"(?<![0-9a-f])[0-9a-f]{8,40}(?![0-9a-f])", str(version))
    return any(GREPTIME_SHA.startswith(token) for token in tokens)


def prepare_selected(benchmark_repo, archive, operator_root, public):
    fixture = verify_bindings(benchmark_repo)
    sys.path.insert(0, str(benchmark_repo / "src"))
    protocol_module = importlib.import_module("agent_rca_bench.transfer_protocol")
    formal = importlib.import_module("agent_rca_bench.transfer_formal")
    server = importlib.import_module("agent_rca_bench.greptimedb.server")
    openrca = importlib.import_module("agent_rca_bench.datasets.openrca2")
    for module in (protocol_module, formal, server, openrca):
        if not Path(module.__file__).resolve().is_relative_to((benchmark_repo / "src").resolve()):
            raise ValueError("import_not_from_pinned_checkout")
    original, cohort = protocol_module.load_transfer_protocol(fixture)
    if original.greptimedb_revision != GREPTIME_SHA or original.greptimedb_build_profile != "release":
        raise ValueError("original_release_protocol_drifted")
    derived = original.model_copy(update={"greptimedb_build_profile": "debug"})
    original_dump = original.model_dump(mode="json")
    derived_dump = derived.model_dump(mode="json")
    if {k for k in original_dump if original_dump[k] != derived_dump[k]} != {"greptimedb_build_profile"}:
        raise ValueError("derived_protocol_changed_unregistered_fields")
    registration = {
        "condition": "derived-debug-backend-causal-discovery-pilot/1",
        "official_release_reproduction": False,
        "original_protocol_sha256": PROTOCOL_SHA256,
        "registered_changes": {"greptimedb_build_profile": {"from": "release", "to": "debug"},
            "upstream_build_features": ["pg_kvbackend", "mysql_kvbackend", "vector_index"]},
        "upstream_artifact_id": 9878363388, "upstream_run_id": 33714665221,
        "upstream_tar_sha256": TAR_SHA256,
        "selected_cases_in_execution_order": list(SELECTED),
        "unchanged": ["source_bindings", "case_specs", "oracles", "scorer", "full_no_model_gates"],
        "derived_protocol": derived_dump,
    }
    write_json(operator_root / "derived_condition_registration.json", registration)
    public["gates"]["source_contract_bindings"] = True
    greptime_repo = operator_root / "greptimedb"
    with (operator_root / "checkout.log").open("w") as log:
        checkout_greptime(greptime_repo, log)
    binary_hash = extract_verified_binary(archive, greptime_repo / "target/debug/greptime")
    observed = server.inspect_checkout(greptime_repo, build_profile="debug")
    write_json(operator_root / "binary_checkout_observation.json", observed)
    if observed["head"] != GREPTIME_SHA or not version_matches_revision(observed["binary_version"]):
        raise ValueError("binary_version_or_checkout_binding_failed")
    public["binary_sha256"] = binary_hash
    public["gates"]["binary_checkout_version_binding"] = True
    specs = {spec.opaque_case_id: spec for spec in cohort.selected_cases}
    if any(case_id not in specs for case_id in SELECTED):
        raise ValueError("selected_case_not_bound")
    cache = operator_root / "source_cache/openrca2"
    for case_id in SELECTED:
        public_case = {"case_id": case_id, "all_no_model_gates_passed": False}
        public["cases"].append(public_case)
        spec = specs[case_id]
        if cohort.adapter_for(case_id) == "openrca2":
            openrca.OpenRCA2Repository(cache).fetch_case(spec.source_case,
                                                       require_observable_alert=False)
        config = formal.TransferEnvironmentConfig(
            cache_dir=cache, manifest_path=cache / "manifest.jsonl",
            greptimedb_repo=greptime_repo, run_dir=operator_root / "runs" / case_id,
            database=case_id.replace("-", "_"),
            node_cache_dir=operator_root / "source_cache/rca100")
        # This is the intact pinned preparation path: exclusive DB, full
        # Prometheus/Loki/Tempo stack, ingestion, isolation, fidelity, graph,
        # mechanism and PromQL checks. No optional gate is bypassed.
        with formal.prepare_transfer_environment(derived, spec, config) as prepared:
            audit = prepared.source_audit
            if audit["no_model_gates"].get("all_passed") is not True:
                raise ValueError("selected_no_model_gates_failed")
            public_case.update(all_no_model_gates_passed=True,
                gate_count=len(audit["no_model_gates"]) - 1)
        # Cleanup mutates the audit's process_stopped field; persist after exit.
        write_json(operator_root / (case_id + "_operator_audit.json"), audit)
    public["gates"]["selected_full_no_model_gates"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark-repo", type=Path, required=True)
    parser.add_argument("--bins-tar", type=Path, required=True)
    parser.add_argument("--operator-root", type=Path)
    parser.add_argument("--public-receipt", type=Path, required=True)
    args = parser.parse_args()
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    root = (args.operator_root or runner_temp / ("rca-backend-" + str(uuid.uuid4()))).resolve()
    if not root.is_relative_to(runner_temp) or root == runner_temp or root.exists():
        parser.error("operator_root_must_be_new_directory_inside_RUNNER_TEMP")
    root.mkdir(parents=True, mode=0o700)
    public = {"stage": "derived_debug_selected_official_no_model_preflight",
        "scored_trials_launched": 0, "official_release_reproduction": False,
        "benchmark_revision": BENCHMARK_SHA, "greptimedb_revision": GREPTIME_SHA,
        "build_profile": "debug", "tar_sha256": TAR_SHA256,
        "upstream_artifact_id": 9878363388,
        "gates": {"source_contract_bindings": False,
                  "binary_checkout_version_binding": False,
                  "selected_full_no_model_gates": False}, "cases": []}
    exit_code = 0
    with (root / "operator_output.log").open("w") as log:
        try:
            with redirect_stdout(log), redirect_stderr(log):
                prepare_selected(args.benchmark_repo.resolve(), args.bins_tar.resolve(), root, public)
        except Exception as error:
            traceback.print_exc(file=log)
            public["failure_type"] = type(error).__name__
            exit_code = 1
    args.public_receipt.parent.mkdir(parents=True, exist_ok=True)
    write_json(args.public_receipt, public)
    print(json.dumps(public, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
