"""Seeded campaigns check full persistent state after every real MCP operation."""
import asyncio
import copy
import json

import pytest

from simlab.campaign import campaign_matrix, generate_manifest, read_manifest


def test_manifests_are_deterministic_and_include_retries_and_conflicts():
    manifest = generate_manifest(7, 50)
    assert manifest == generate_manifest(7, 50)
    assert manifest != generate_manifest(11, 50)
    assert manifest["actions"][7] == manifest["actions"][6]
    assert manifest["actions"][11]["arguments"]["idempotency_key"] == manifest["actions"][10]["arguments"]["idempotency_key"]
    assert manifest["actions"][11]["arguments"]["status"] != manifest["actions"][10]["arguments"]["status"]
    assert {action["approval"] for action in manifest["actions"]} >= {"accept", "decline", "cancel", "wrong_digest"}


@pytest.mark.parametrize("patch", ["version", "extra", "empty", "too_many", "approval", "record", "argument"])
def test_invalid_replay_manifests_fail_before_starting_simulation(tmp_path, patch):
    manifest = copy.deepcopy(generate_manifest(7, 5))
    if patch == "version":
        manifest["schema_version"] = 99
    elif patch == "extra":
        manifest["execute_command"] = "not allowed"
    elif patch == "empty":
        manifest["actions"] = []
    elif patch == "too_many":
        manifest["actions"] *= 41
    elif patch == "approval":
        manifest["actions"][0]["approval"] = "approve-everything"
    elif patch == "record":
        manifest["actions"][0]["arguments"]["record_id"] = "../../outside"
    else:
        manifest["actions"][0]["arguments"]["override"] = True
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError):
        read_manifest(path)


@pytest.mark.parametrize("mode", ["vulnerable", "hardened"])
@pytest.mark.parametrize("transport", ["stdio", "sse"])
@pytest.mark.parametrize("seed", [7, 11])
def test_generated_campaign_preserves_oracle_invariants(tmp_path, mode, transport, seed):
    rows = asyncio.run(campaign_matrix(tmp_path / "campaign", mode, transport, seed=seed, steps=24))
    assert len(rows) == 24
    assert not [row for row in rows if not row["passed"]]
    assert [row["campaign_step"] for row in rows] == list(range(24))
    assert all(row["campaign_seed"] == seed and row["feature"] == "Seeded campaigns" for row in rows)
    if mode == "hardened":
        assert rows[7]["callbacks"] == []  # Retry or rejection needs no new confirmation.


def test_saved_campaign_replays_the_same_actions_and_outcomes(tmp_path):
    original = asyncio.run(campaign_matrix(tmp_path / "first", "hardened", "stdio", seed=11, steps=16))
    repeated = asyncio.run(campaign_matrix(tmp_path / "replayed", "hardened", "stdio",
                                           manifest_path=tmp_path / "first" / "campaign.json"))
    keys = ("arguments", "approval", "expected", "published_record", "receipt_count", "passed")
    assert [{key: row[key] for key in keys} for row in original] == [{key: row[key] for key in keys} for row in repeated]
