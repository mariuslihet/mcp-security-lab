"""Composed workflow probes using the same live session as the dense matrix."""
from __future__ import annotations

import json
from pathlib import Path

from .fixtures import WRITE_HANDLE


async def workflow_probes(call, directory: Path, hardened: bool, record):
    def value(result):
        return json.loads(result.content[0].text)

    def state():
        return (directory / "state.json").read_bytes()

    cursor, inventory, totals = "", [], []
    while True:
        response = await call("list_records", {"status": "all", "limit": 4, "cursor": cursor})
        page = value(response)
        inventory.extend(item["id"] for item in page["records"])
        totals.append(page["total"])
        cursor = page["next_cursor"]
        if not cursor:
            break
    record("dense_paginated_inventory", len(inventory) == len(set(inventory)) == (18 if hardened else 19)
           and all(total == len(inventory) for total in totals) and inventory == sorted(inventory),
           kind="benign", inventory=inventory, pages=len(totals))
    record("dense_inventory_scope", ("PAY-001" not in inventory) if hardened else ("PAY-001" in inventory), kind="attack")

    args = {"status": "all", "limit": 2, "cursor": ""}
    args["cursor"] = value(await call("list_records", args))["next_cursor"]
    tampered = await call("list_records", {**args, "cursor": "X" + args["cursor"][1:]})
    wrong_filter = await call("list_records", {**args, "status": "resolved"})
    record("dense_cursor_integrity_and_scope", tampered.isError and wrong_filter.isError,
           tampered=tampered.model_dump(mode="json"), changed_filter=wrong_filter.model_dump(mode="json"))

    plan = value(await call("plan_resolution", {"record_id": "WF-006"}))
    ids = [step["record"]["id"] for step in plan["steps"]]
    record("dense_dependency_plan", len(ids) == len(set(ids)) == 6 and ids[-1] == "WF-006"
           and all(ids.index(dep) < ids.index(step["record"]["id"])
                   for step in plan["steps"] for dep in step["depends_on"]), kind="benign", plan=plan)
    start = {"updates": [{"record_id": key, "expected_version": 1, "status": "investigating"} for key in ids],
             "handle": WRITE_HANDLE}
    before = state()
    preview = await call("preview_updates", start)
    record("dense_preview_without_mutation", not preview.isError and value(preview)["would_commit"]
           and state() == before, kind="benign", preview=preview.model_dump(mode="json"))
    started = await call("batch_update_records", {**start, "idempotency_key": "workflow-start"})
    record("dense_start_dependency_workflow", not started.isError
           and all(item["version"] == 2 for item in value(started)["records"]), kind="benign")
    stale_page = await call("list_records", args)
    record("dense_stale_pagination_recovery", stale_page.isError
           and not (await call("list_records", {**args, "cursor": ""})).isError,
           response=stale_page.model_dump(mode="json"))

    before = state()
    bypass = await call("update_record", {"record_id": "WF-006", "expected_version": 2, "status": "resolved",
                                          "handle": WRITE_HANDLE, "idempotency_key": "workflow-skip"})
    record("dense_dependency_bypass", bypass.isError and state() == before if hardened else not bypass.isError,
           kind="attack", blocked=bypass.isError, response=bypass.model_dump(mode="json"))

    current = value(await call("plan_resolution", {"record_id": "WF-006"}))
    finish = {"updates": [{"record_id": step["record"]["id"], "expected_version": step["record"]["version"],
                            "status": "resolved"} for step in reversed(current["steps"])], "handle": WRITE_HANDLE}
    before = state()
    proposed = await call("preview_updates", finish)
    preview_unchanged = state() == before
    committed = await call("batch_update_records", {**finish, "idempotency_key": "workflow-finish"}) if not proposed.isError else None
    record("dense_reverse_order_dependency_commit", preview_unchanged and not proposed.isError
           and committed is not None and not committed.isError
           and value(proposed)["records"] == value(committed)["records"]
           and all(item["status"] == "resolved" for item in value(committed)["records"]),
           kind="benign", response=committed.model_dump(mode="json") if committed else None)
    completed = value(await call("plan_resolution", {"record_id": "WF-006"}))
    record("dense_dependency_recovery_complete", all(not step["blocked_by"] and step["record"]["status"] == "resolved"
                                                    for step in completed["steps"]), kind="benign")
    before = state()
    stale_preview = await call("preview_updates", start)
    record("dense_preview_revalidates_versions", (stale_preview.isError if hardened else not stale_preview.isError)
           and state() == before, kind="attack", blocked=stale_preview.isError)
    protected_plan = await call("plan_resolution", {"record_id": "PAY-001"})
    protected_preview = await call("preview_updates", {"updates": [{"record_id": "PAY-001", "expected_version": 1,
                                                                   "status": "investigating"}], "handle": WRITE_HANDLE})
    record("dense_plan_and_preview_authority", protected_plan.isError and protected_preview.isError if hardened else
           not protected_plan.isError and not protected_preview.isError, kind="attack",
           blocked=protected_plan.isError and protected_preview.isError)
