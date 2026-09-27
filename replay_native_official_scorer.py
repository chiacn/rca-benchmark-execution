"""Operator-only no-model replay against the pinned production scorer.

Uses the upstream test fixture constructors and selected hidden specs only
within this process. Prints boolean checks, never queries, labels or rows.
Run from the pinned benchmark environment with --benchmark-repo PATH.
These are synthetic scorer-contract checks, not live incident/model scores.
"""
from __future__ import annotations

import argparse
import importlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import actions_backend_preflight as preparation
from persistent_raw_mailbox import SCORER_SHA256, unchanged_causal_score


def replay(benchmark_repo):
    fixture = preparation.verify_bindings(benchmark_repo)
    source = benchmark_repo / 'src/agent_rca_bench/transfer_scorer.py'
    if preparation.sha256_file(source) != SCORER_SHA256:
        raise ValueError('pinned_scorer_hash_mismatch')
    sys.path.insert(0, str(benchmark_repo / 'src'))
    contracts = importlib.import_module('agent_rca_bench.contracts')
    scorer = importlib.import_module('agent_rca_bench.transfer_scorer')
    protocol_module = importlib.import_module('agent_rca_bench.transfer_protocol')
    protocol, cohort = protocol_module.load_transfer_protocol(fixture)
    fixture_loader = importlib.util.spec_from_file_location(
        'operator_upstream_scorer_fixtures', benchmark_repo / 'tests/test_transfer_scorer.py')
    helpers = importlib.util.module_from_spec(fixture_loader)
    fixture_loader.loader.exec_module(helpers)
    specs = {item.opaque_case_id: item for item in cohort.selected_cases}
    checks = []

    def compare(case, api_run, variant, expected_diagnosis, expected_evidence):
        native_fields = {key: getattr(api_run, key) for key in type(api_run).model_fields}
        native_fields.update(runner='codex-cli-subscription', api_transport=None,
                             max_output_tokens=None, usage=None, responses=None)
        native = SimpleNamespace(**native_fields)
        api = scorer.evaluate_transfer_run(api_run, case,
            expected_model='test-model', expected_transport=contracts.ApiTransport.OPENAI_RESPONSES,
            expected_reasoning_effort='high', expected_max_output_tokens=16384, max_tool_calls=48)
        result = unchanged_causal_score(scorer, native, case, 'test-model', 'high', 48)
        primary = result['primary_causal_endpoints']
        api_fields = api.model_dump(mode='json')
        assert all(primary[key] == api_fields[key] for key in primary), 'causal_endpoint_parity_failed'
        assert primary['diagnosis_correct'] is expected_diagnosis, 'unexpected_fixture_diagnosis'
        assert primary['required_evidence_covered'] is expected_evidence, (
            'unexpected_fixture_grounding:' + case.opaque_case_id + ':' + variant)
        assert result['unmodified_scorer_output']['execution_reliability'] is False
        assert result['unmodified_scorer_output']['success'] is False
        assert result['official_completion_fields_applicable'] is False
        assert result['native_execution_reliability'] is True
        checks.append({'case_id': case.opaque_case_id, 'fixture': variant,
                       'causal_endpoint_parity': True, 'expected_diagnosis': expected_diagnosis,
                       'expected_grounding': expected_evidence,
                       'truthful_native_runner_guard': True})

    for case_id in preparation.SELECTED:
        case = specs[case_id]
        is_delay = case.causal_scope is contracts.CausalScope.DEPENDENCY_EDGE
        query = helpers._delay_query(case) if is_delay else helpers._metric_query(case)
        rows = helpers._delay_result(case) if is_delay else helpers._metric_result(case)
        api_run = helpers._run(case, query, rows)
        compare(case, api_run, 'upstream_positive', True, True)
        wrong_diagnosis = api_run.diagnosis.model_copy(update={'mechanism_code': contracts.MechanismCode.UNKNOWN})
        compare(case, api_run.model_copy(update={'diagnosis': wrong_diagnosis}),
                'wrong_mechanism', False, True)
        if is_delay:
            bad_query = helpers._delay_query(case, wrong_parent=True)
        else:
            signal = case.mechanism_evidence
            # Keep a genuine telemetry SQL citation while using the wrong
            # source identity, matching upstream's identity-negative family.
            # SELECT 1 is not an evidence citation and correctly yields null
            # (not estimable), rather than a measured false grounding.
            correct_identity = f"{signal.identity_column} = '{signal.identity_value}'"
            bad_query = query.replace(correct_identity,
                                      f"{signal.identity_column} = 'synthetic-wrong-entity'")
            assert bad_query != query, 'negative_identity_mutation_not_applied'
        bad_run = helpers._run(case, bad_query, rows)
        compare(case, bad_run, 'invalid_evidence_lineage', True, False)
        no_evidence_run = helpers._run(case, 'SELECT 1', rows)
        compare(case, no_evidence_run, 'non_telemetry_citation_not_estimable', True, None)
    return {'stage': 'synthetic_native_pinned_scorer_contract_replay',
            'scored_model_calls': 0, 'live_incident_scores': 0,
            'scorer_sha256': SCORER_SHA256, 'all_checks_passed': True, 'checks': checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--benchmark-repo', required=True, type=Path)
    args = parser.parse_args()
    repo = args.benchmark_repo.resolve()
    old_cwd = Path.cwd()
    try:
        os.chdir(repo)
        result = replay(repo)
    finally:
        os.chdir(old_cwd)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
