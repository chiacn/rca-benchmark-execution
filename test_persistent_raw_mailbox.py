import base64
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import uuid

from persistent_raw_mailbox import CHUNK_BYTES, PayloadVault, RawMailboxBridge, unchanged_causal_score
from mailbox_runner import bounded_json, encode


class LosslessFramingTests(unittest.TestCase):
    def test_large_official_output_reassembled_without_truncation(self):
        original = {"content": json.dumps({"rows": [[i, "row" * 100] for i in range(1000)],
                                          "truncated": False, "query_id": "official-q1"}),
                    "is_error": False, "remaining": 47}
        vault = PayloadVault()
        descriptor = vault.pack(original)
        raw = b""
        for index in range(descriptor["total"]):
            chunk = vault.fetch({"transfer_id": descriptor["transfer_id"], "index": index})
            bounded_json(chunk)
            self.assertLess(len(encode(chunk)), 65536)
            part = b"".join(base64.b64decode(s) for s in chunk["segments"])
            self.assertEqual(hashlib.sha256(part).hexdigest(), chunk["sha256"])
            raw += part
        self.assertEqual(hashlib.sha256(raw).hexdigest(), descriptor["sha256"])
        self.assertEqual(json.loads(raw), original)
        self.assertFalse(json.loads(json.loads(raw)["content"])["truncated"])

    def test_uploaded_diagnosis_integrity_and_conflict(self):
        value = {"explanation": "private" * 20000}
        raw = encode(value)
        token, vault = str(uuid.uuid4()), PayloadVault()
        total = (len(raw) + CHUNK_BYTES - 1) // CHUNK_BYTES
        requests = []
        for index in range(total):
            chunk = raw[index * CHUNK_BYTES:(index + 1) * CHUNK_BYTES]
            request = {"transfer_id": token, "index": index, "total": total, "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "segments": [base64.b64encode(chunk[start:start + 4608]).decode()
                             for start in range(0, len(chunk), 4608)]}
            requests.append(request)
            bounded_json(request)
            vault.upload(request)
        self.assertEqual(vault.uploaded(token), value)
        self.assertTrue(vault.upload(requests[0])["complete"])
        changed = dict(requests[0], sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "metadata_conflict"):
            vault.upload(changed)

    def test_native_causal_scoring_does_not_project_api_metadata(self):
        native = SimpleNamespace(runner="codex-cli-subscription", api_transport=None,
                                 error=None, tool_budget_exhausted=False, tool_calls=[], rejected_tool_calls=[])
        observed = []
        class Result:
            def model_dump(self, **_):
                return {k: True for k in ("diagnosis_correct", "causal_locus_match", "causal_scope_match",
                    "fault_category_match", "mechanism_code_match", "causal_locus_evidence_match",
                    "mechanism_evidence_match", "required_evidence_covered", "citations_execution_valid",
                    "grounding_not_estimable_reason", "evidence_audit_failure_reasons")}
        scorer = SimpleNamespace(evaluate_transfer_run=lambda run, *a, **k: observed.append(run) or Result())
        result = unchanged_causal_score(scorer, native, object(), "terra", "high", 48)
        self.assertIs(observed[0], native)
        self.assertEqual(native.runner, "codex-cli-subscription")
        self.assertIsNone(native.api_transport)
        self.assertFalse(result["official_completion_fields_applicable"])
        self.assertFalse(result["official_api_runner_contract_match"])


class DraftAndBudgetBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        class Input:
            fault_taxonomy = []
            database = "semantic_rca_transfer_011"
            def model_copy(self, update):
                return self
            def model_dump(self, **_):
                return {"database": self.database, "case_token": "incident", "system": "source_system",
                        "dataset": "oracle_operator_only", "time_start": 1, "time_end": 3,
                        "alert_time": 2, "alert_text": "generic anomaly", "fault_taxonomy": []}
        class Trace:
            def __init__(self, n): self.n = n
            def model_dump(self, **_): return {"query_id": "q" + str(self.n)}
        class Session:
            def __init__(self, *_, max_tool_calls, **kwargs):
                self.max = max_tool_calls
                self.tool_calls = []
                self.rejected_tool_calls = []
                self.tool_calls_requested = 0
                self.tool_budget_exhausted = False
            @property
            def remaining(self): return self.max - len(self.tool_calls)
            def invoke(self, name, arguments):
                self.tool_calls_requested += 1
                if self.remaining == 0:
                    self.tool_budget_exhausted = True
                    return SimpleNamespace(content="budget exhausted", is_error=True, remaining=0)
                self.tool_calls.append(Trace(len(self.tool_calls) + 1))
                return SimpleNamespace(content=json.dumps({"query_id": "q" + str(len(self.tool_calls))}),
                                       is_error=False, remaining=self.remaining)
            def validate_diagnosis_citations(self, output):
                if output.get("citation") not in {"q" + str(i + 1) for i in range(len(self.tool_calls))}:
                    raise ValueError("invalid query citation")
        class Diagnosis:
            @classmethod
            def model_validate(cls, output):
                return SimpleNamespace(model_dump=lambda **_: dict(output))
        agent = SimpleNamespace(InvestigationSession=Session,
            _investigation_tools=lambda *a, **kw: [{"name": "execute_sql"}],
            _validate_diagnosis_output=lambda value: dict(value),
            _system_prompt=lambda visibility: "official system",
            _incident_prompt=lambda case, *a: "Database: " + case.database,
            _submit_tool=lambda *a: {"name": "submit_diagnosis"})
        prepared = SimpleNamespace(case=SimpleNamespace(input=Input()), semantic_coverage={}, client=object(), spec=object())
        contracts = SimpleNamespace(Visibility=SimpleNamespace(RAW=SimpleNamespace(value="raw")), Diagnosis=Diagnosis)
        self.bridge = RawMailboxBridge(prepared, SimpleNamespace(max_tool_calls=48, max_turns=58), root,
            "terra", "high", None, agent=agent, contracts=contracts, scorer=object(), gateway_factory=lambda *a: object())

    def tearDown(self): self.temp.cleanup()

    def unpack(self, packed): return json.loads(packed["payload_json"])

    def test_pass_drafts_cannot_freeze_or_score_shared_budget(self):
        for pass_index in range(3):
            output = self.unpack(self.bridge.invoke("execute_sql", {"query": "SELECT 1"}))
            self.assertEqual(output["remaining"], 47 - pass_index)
            draft = self.unpack(self.bridge.submit({"citation": "q1"}))
            self.assertTrue(draft["accepted"])
            self.assertFalse(draft["frozen"])
            self.assertFalse(self.bridge.closed)
        self.assertEqual(len(self.bridge.session.tool_calls), 3)
        self.assertFalse((self.bridge.root / "frozen_diagnosis.json").exists())
        self.assertFalse((self.bridge.root / "evaluation.json").exists())
        with self.assertRaisesRegex(ValueError, "authorization_failed"):
            self.bridge.finalize({"operator_nonce": "wrong", "diagnosis": {"citation": "q1"}})

    def test_worker_contract_omits_source_metadata_and_operator_secret(self):
        contract = self.unpack(self.bridge.incident_context({}))
        self.assertEqual(contract["case_input"]["database"], "semantic_rca_transfer_011")
        self.assertNotIn("system", contract["case_input"])
        self.assertNotIn("dataset", contract["case_input"])
        self.assertNotIn(self.bridge.operator_nonce, json.dumps(contract))

    def test_chunk_fetch_does_not_consume_investigation_budget(self):
        descriptor = self.bridge.vault.pack({"content": "x" * 10000})
        self.bridge.vault.fetch({"transfer_id": descriptor["transfer_id"], "index": 0})
        self.assertEqual(self.bridge.session.remaining, 48)

    def test_operator_probe_uses_separate_ledger_and_pristine_guard(self):
        result = self.unpack(self.bridge.operator_preflight({"operator_nonce": self.bridge.operator_nonce}))
        self.assertTrue(result["all_probes_succeeded"])
        self.assertEqual(len(result["probe_tool_calls"]), 2)
        self.assertEqual(result["main_tool_calls_before"], 0)
        self.assertEqual(result["main_tool_calls_after"], 0)
        self.assertEqual(result["main_citations_count"], 0)
        self.assertEqual(result["main_remaining_after"], 48)
        self.assertEqual(self.bridge.session.tool_calls_requested, 0)
        with self.assertRaisesRegex(ValueError, "authorization_failed"):
            self.bridge.operator_preflight({"operator_nonce": "wrong"})
        self.bridge.invoke("execute_sql", {"query": "SELECT 1"})
        with self.assertRaisesRegex(ValueError, "pristine_worker_ledger"):
            self.bridge.operator_preflight({"operator_nonce": self.bridge.operator_nonce})


if __name__ == "__main__":
    unittest.main()
