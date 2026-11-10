import asyncio
import hashlib
import json

import pytest

from simlab.checkpoint import canonical, load_checkpoint
from simlab.graph_campaign import generate_graph_manifest, graph_campaign_matrix


def test_http_checkpoint_preserves_withdrawn_workspace_roots(tmp_path):
    manifest = generate_graph_manifest(19, 50, nodes=16, width=4, parallel_calls=8,
                                       race_topology="mixed", root_churn=True)
    stop = next(index + 1 for index, action in enumerate(manifest["actions"]) if action["label"] == "workspace_withdrawn")
    source, target = tmp_path / "source", tmp_path / "target"
    partial = asyncio.run(graph_campaign_matrix(source, "hardened", "streamable-http", manifest, stop_after=stop))
    assert all(row["passed"] for row in partial)
    _, checkpoint = load_checkpoint(source / "checkpoint.json")
    assert checkpoint["client_root_mode"] == "outside"
    rows = asyncio.run(graph_campaign_matrix(target, "hardened", "streamable-http", manifest,
                                            resume_checkpoint=source / "checkpoint.json"))
    assert all(row["passed"] for row in rows)
    assert rows[stop]["action"]["label"] == "root_boundary_denied"
    assert rows[stop]["responses"][0]["isError"]


@pytest.mark.parametrize("mode", ["hardened", "vulnerable"])
@pytest.mark.parametrize("transport", ["stdio", "sse"])
@pytest.mark.parametrize("boundary", ["compact_catalog", "start_wave"])
def test_graph_campaign_resumes_catalog_faults_state_and_receipts(tmp_path, mode, transport, boundary):
    manifest = generate_graph_manifest(11, 40, nodes=8, width=2, parallel_calls=4)
    stop = next(index + 1 for index, action in enumerate(manifest["actions"]) if action["label"] == boundary)
    original, destination = tmp_path / "original", tmp_path / "continued"
    partial = asyncio.run(graph_campaign_matrix(original, mode, transport, manifest, stop_after=stop))
    assert len(partial) == stop and all(row["passed"] for row in partial)
    checkpoint_before = (original / "checkpoint.json").read_bytes()
    continued = asyncio.run(graph_campaign_matrix(destination, mode, transport, manifest,
                                                  resume_checkpoint=original / "checkpoint.json"))
    assert len(continued) == 40 and all(row["passed"] for row in continued)
    assert [row["responses"] for row in continued[:stop]] == [row["responses"] for row in partial]
    assert (original / "checkpoint.json").read_bytes() == checkpoint_before
    assert "history" in continued[0]["audit"]
    saved_manifest, saved = load_checkpoint(destination / "checkpoint.json")
    assert saved["next_action"] == 40 and saved_manifest == manifest
    if boundary == "start_wave" and mode == "hardened":
        assert continued[stop]["responses"][0]["structuredContent"]["deduplicated"] is True
        assert continued[stop]["notifications"] == []


def test_resume_can_continue_more_than_one_checkpoint_generation(tmp_path):
    manifest = generate_graph_manifest(7, 40, nodes=8, width=2, parallel_calls=4)
    first, second, third = [tmp_path / name for name in ("first", "second", "third")]
    asyncio.run(graph_campaign_matrix(first, "hardened", "stdio", manifest, stop_after=6))
    asyncio.run(graph_campaign_matrix(second, "hardened", "stdio", manifest, stop_after=18,
                                      resume_checkpoint=first / "checkpoint.json"))
    rows = asyncio.run(graph_campaign_matrix(third, "hardened", "stdio", manifest,
                                            resume_checkpoint=second / "checkpoint.json"))
    assert len(rows) == 40 and all(row["passed"] for row in rows)
    assert all(len(path.name) < 100 for path in (third / "history").iterdir())


@pytest.mark.parametrize("change", ["checksum", "manifest", "evidence", "escape"])
def test_checkpoint_corruption_is_rejected_before_resume(tmp_path, change):
    manifest = generate_graph_manifest(7, 40, nodes=8, width=2, parallel_calls=4)
    original = tmp_path / "original"
    asyncio.run(graph_campaign_matrix(original, "hardened", "stdio", manifest, stop_after=1))
    path = original / "checkpoint.json"
    envelope = json.loads(path.read_text(encoding="utf-8"))
    if change == "checksum":
        envelope["sha256"] = "0" * 64
        path.write_text(json.dumps(envelope), encoding="utf-8")
    elif change == "manifest":
        manifest["seed"] = 12
        (original / "campaign.json").write_text(json.dumps(manifest), encoding="utf-8")
    elif change == "evidence":
        audit = original / "wire.jsonl"
        data = audit.read_bytes()
        audit.write_bytes(b"X" + data[1:])
    else:
        entry = envelope["payload"]["evidence"].pop("wire.jsonl")
        envelope["payload"]["evidence"]["../outside.jsonl"] = entry
        envelope["payload"]["rows"][0]["audit"] = "../outside.jsonl"
        envelope["sha256"] = hashlib.sha256(canonical(envelope["payload"])).hexdigest()
        path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(ValueError):
        load_checkpoint(path)


def test_uncheckpointed_fixture_mutations_are_not_restored(tmp_path):
    manifest = generate_graph_manifest(7, 40, nodes=8, width=2, parallel_calls=4)
    original = tmp_path / "original"
    asyncio.run(graph_campaign_matrix(original, "hardened", "stdio", manifest, stop_after=6))
    state_path = original / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["records"]["GR-000"]["version"] = 999
    state_path.write_text(json.dumps(state), encoding="utf-8")
    with (original / "wire.jsonl").open("a", encoding="utf-8") as stream:
        stream.write('{"uncheckpointed":true}\n')
    rows = asyncio.run(graph_campaign_matrix(tmp_path / "continued", "hardened", "stdio", manifest,
                                            resume_checkpoint=original / "checkpoint.json"))
    assert all(row["passed"] for row in rows)
    assert "uncheckpointed" not in (tmp_path / "continued" / "history" / next(
        path.name for path in (tmp_path / "continued" / "history").iterdir() if path.name.endswith("wire.jsonl"))).read_text(encoding="utf-8")


def test_rehashed_but_inconsistent_state_is_rejected_by_reference_oracle(tmp_path):
    manifest = generate_graph_manifest(7, 40, nodes=8, width=2, parallel_calls=4)
    original = tmp_path / "original"
    asyncio.run(graph_campaign_matrix(original, "hardened", "stdio", manifest, stop_after=0))
    path = original / "checkpoint.json"
    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["payload"]["state"]["records"]["GR-000"]["version"] = 999
    envelope["sha256"] = hashlib.sha256(canonical(envelope["payload"])).hexdigest()
    path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(ValueError, match="reference oracle"):
        asyncio.run(graph_campaign_matrix(tmp_path / "rejected", "hardened", "stdio", manifest, resume_checkpoint=path))
    assert not (tmp_path / "rejected" / "wire.jsonl").exists()


@pytest.mark.parametrize("mode,transport", [("vulnerable", "stdio"), ("hardened", "sse")])
def test_resume_cannot_change_mode_or_transport(tmp_path, mode, transport):
    manifest = generate_graph_manifest(7, 40, nodes=8, width=2, parallel_calls=4)
    original = tmp_path / "original"
    asyncio.run(graph_campaign_matrix(original, "hardened", "stdio", manifest, stop_after=0))
    with pytest.raises(ValueError, match="preserve"):
        asyncio.run(graph_campaign_matrix(tmp_path / "rejected", mode, transport, manifest,
                                          resume_checkpoint=original / "checkpoint.json"))
    assert not (tmp_path / "rejected").exists()
