import asyncio
import copy
import json

import pytest

from simlab.campaign import campaign_matrix, read_manifest
from simlab.graph_campaign import generate_graph_manifest, validate_graph_manifest


def test_graph_manifest_generation_is_deterministic_and_contains_composed_stress():
    manifest = generate_graph_manifest(11, 60, nodes=32, width=4, parallel_calls=16)
    assert manifest == generate_graph_manifest(11, 60, nodes=32, width=4, parallel_calls=16)
    assert len(manifest["graph"]) == 32 and len(manifest["actions"]) == 60
    assert {action["label"] for action in manifest["actions"]} >= {
        "lost_ack_retry", "blocked_tip", "receipt_payload_conflict", "dependency_wave", "completed_analysis", "replayed_race"}
    assert len(next(action for action in manifest["actions"] if action["kind"] == "race")["requests"]) == 16


@pytest.mark.parametrize("problem", ["cycle", "outside_edge", "unknown_tool", "outside_record", "race_mismatch", "race_duplicate_keys"])
def test_graph_manifest_rejects_unsafe_or_ambiguous_actions(tmp_path, problem):
    manifest = copy.deepcopy(generate_graph_manifest(7, 40, nodes=16, width=4))
    if problem == "cycle":
        manifest["graph"]["GR-000"] = ["GR-015"]
    elif problem == "outside_edge":
        manifest["graph"]["GR-015"] = ["PAY-001"]
    elif problem == "unknown_tool":
        manifest["actions"][0]["tool"] = "execute_command"
    elif problem == "outside_record":
        manifest["actions"][0]["arguments"]["record_id"] = "../../outside"
    else:
        race = next(action for action in manifest["actions"] if action["kind"] == "race")
        if problem == "race_mismatch":
            race["requests"][1]["updates"][0]["status"] = "open"
        else:
            race["requests"][1]["idempotency_key"] = race["requests"][0]["idempotency_key"]
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError):
        read_manifest(path)


@pytest.mark.parametrize("mode", ["vulnerable", "hardened"])
@pytest.mark.parametrize("transport", ["stdio", "sse"])
def test_graph_campaign_checks_state_receipts_notifications_and_legal_races(tmp_path, mode, transport):
    rows = asyncio.run(campaign_matrix(tmp_path / "graph-campaign", mode, transport, seed=11, steps=40,
                                       graph_nodes=16, graph_width=4, parallel_calls=8))
    failures = [row for row in rows if not row["passed"]]
    assert not failures, failures
    assert len(rows) == 40
    assert all(row["state_matches_oracle"] and row["resource_notifications_match"] and row["catalog_notifications_match"] for row in rows)
    race = next(row for row in rows if row["action"]["label"] == "overlapping_root_resolutions")
    assert race["expected"]["accepted"] == (1 if mode == "hardened" else 8)
    retry = next(row for row in rows if row["action"]["label"] == "lost_ack_retry")
    if mode == "hardened":
        assert retry["responses"][0]["structuredContent"]["deduplicated"] is True
        assert retry["notifications"] == []


@pytest.mark.parametrize("nodes,width,parallel", [(32, 4, 16), (64, 8, 24), (128, 4, 32)])
def test_hardened_graph_stress_at_larger_sizes(tmp_path, nodes, width, parallel):
    rows = asyncio.run(campaign_matrix(tmp_path / "stress", "hardened", "stdio", seed=7, steps=80,
                                       graph_nodes=nodes, graph_width=width, parallel_calls=parallel))
    assert not [row for row in rows if not row["passed"]]
    completed = next(row for row in rows if row["action"]["label"] == "completed_analysis")
    assert completed["responses"][0]["structuredContent"]["unresolved"] == []
    assert max(row["receipt_count"] for row in rows) >= (nodes + 15) // 16


def test_dependency_graph_campaign_can_replay_saved_manifest(tmp_path):
    original = asyncio.run(campaign_matrix(tmp_path / "original", "hardened", "stdio", seed=11, steps=40,
                                           graph_nodes=16, graph_width=4, parallel_calls=8))
    repeated = asyncio.run(campaign_matrix(tmp_path / "replay", "hardened", "stdio",
                                           manifest_path=tmp_path / "original" / "campaign.json"))
    assert [row["action"] for row in original] == [row["action"] for row in repeated]
    assert all(row["passed"] for row in repeated)
    # Race winners may differ, but every result must match a legal serialization.
    assert [row["receipt_count"] for row in original] == [row["receipt_count"] for row in repeated]
