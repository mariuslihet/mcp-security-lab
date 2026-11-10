"""Read-only outage propagation and executable, optimistic recovery schedules."""
from collections import deque
import copy
import json

from jsonschema import Draft202012Validator

from .controls import Denied, Firewall, SCHEMAS


class GraphOperations:
    def __init__(self, store, config, hardened):
        self.store, self.config, self.hardened = store, config, hardened

    def validate(self, name, arguments):
        # Bounds also apply to the intentionally vulnerable comparison arm.
        if not Draft202012Validator(SCHEMAS[name]).is_valid(arguments):
            raise Denied("argument_schema_denied")
        if self.hardened:
            Firewall(self.config).check("sim_" + name, arguments)
        return json.loads(self.store.path.read_text(encoding="utf-8"))["records"]

    def failure_cascade(self, arguments):
        records = self.validate("simulate_dependency_outage", arguments)
        failed = sorted(arguments["failed_records"])
        if any(key not in records for key in failed):
            raise Denied("record_not_found")
        visible = set(self.config["allowed_records"]) if self.hardened else set(records)
        children = {key: [] for key in visible}
        for child in sorted(visible):
            for parent in self.config.get("dependencies", {}).get(child, []):
                if parent in children:
                    children[parent].append(child)
        paths, queue = {key: [key] for key in failed}, deque(failed)
        while queue:
            parent = queue.popleft()
            for child in children.get(parent, []):
                if child not in paths:
                    paths[child] = paths[parent] + [child]
                    queue.append(child)
        # Reuse closure checks to reject missing/protected prerequisites and cycles.
        for key in paths:
            self.store._resolution_steps(key, records, self.hardened)
        impacted = sorted(paths)
        return {"failed_records": failed, "impacted_records": impacted,
                "waves": [[key for key in impacted if len(paths[key]) == depth]
                          for depth in range(1, max(map(len, paths.values())) + 1)],
                "paths": {key: paths[key] for key in impacted},
                "unaffected_count": len(visible - set(paths)),
                "snapshot": [copy.deepcopy(records[key]) for key in impacted]}

    def plan_recovery(self, arguments):
        records = self.validate("plan_recovery", arguments)
        steps = self.store._resolution_steps(arguments["record_id"], records, self.hardened)
        selected = sorted(step["record"]["id"] for step in steps)
        proposed = {key: copy.deepcopy(records[key]) for key in selected}
        waves, limit = [], arguments["max_parallel"]
        while any(record["status"] != "resolved" for record in proposed.values()):
            ready = []
            for key in selected:
                record = proposed[key]
                if record["status"] == "resolved":
                    continue
                target = "investigating" if record["status"] == "open" else "resolved"
                if target == "resolved" and any(proposed[parent]["status"] != "resolved"
                        for parent in self.config.get("dependencies", {}).get(key, [])):
                    continue
                ready.append({"record_id": key, "expected_version": record["version"], "status": target})
            # Resolving ready records releases prerequisite pressure first. Nodes
            # in a wave use the state at its beginning, so individual calls may race.
            ready.sort(key=lambda update: (update["status"] != "resolved", update["record_id"]))
            wave = ready[:limit]
            if not wave:
                raise Denied("recovery_plan_blocked")
            waves.append(wave)
            for update in wave:
                proposed[update["record_id"]].update(status=update["status"], version=update["expected_version"] + 1)
        return {"record_id": arguments["record_id"], "max_parallel": limit, "waves": waves,
                "total_updates": sum(map(len, waves)), "snapshot": [copy.deepcopy(records[key]) for key in selected]}
