"""Read-only outage propagation and executable, optimistic recovery schedules."""
from collections import deque
import copy
import json
import heapq

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

    def recovery_resilience(self, arguments):
        from .resilience import simulate
        records = self.resilience_inputs(arguments)
        return simulate(arguments, self.config.get("dependencies", {}), records)

    def recovery_utilization(self, arguments):
        from .resilience import audit
        from .trace_diagnostics import utilization
        self.validate("analyze_recovery_utilization", arguments)
        records = self.resilience_inputs(arguments["scenario"])
        if not audit(arguments["scenario"], self.config.get("dependencies", {}), records, arguments["trace"])["valid"]:
            raise Denied("recovery_trace_invalid")
        return utilization(arguments["scenario"], arguments["trace"])

    def compare_strategies(self, arguments):
        from .recovery_decisions import compare
        self.validate("compare_recovery_strategies", arguments)
        records = self.resilience_inputs(arguments["scenario"])
        labels = [row["label"] for row in arguments["strategies"]]
        if len(set(labels)) != len(labels) or any(outage["worker"] >= row["max_parallel"]
                for row in arguments["strategies"] for outage in arguments["scenario"]["worker_outages"]):
            raise Denied("comparison_strategies_invalid")
        return compare(arguments, self.config.get("dependencies", {}), records)

    def search_mitigations(self, arguments):
        from .counterfactuals import mitigation_search
        self.validate("search_recovery_mitigations", arguments)
        records = self.resilience_inputs(arguments["scenario"])
        if any(row["index"] >= len(arguments["scenario"]["faults" if row["kind"] == "fault" else "worker_outages"])
               for row in arguments["candidates"]):
            raise Denied("mitigation_candidate_invalid")
        return mitigation_search(arguments, self.config.get("dependencies", {}), records)

    def recovery_sensitivity(self, arguments):
        from .counterfactuals import duration_sensitivity
        self.validate("analyze_recovery_sensitivity", arguments)
        records = self.resilience_inputs(arguments["scenario"])
        largest = max(arguments["duration_percent"])
        if any((row[phase] * largest + 99) // 100 > 1000 for row in arguments["scenario"]["durations"]
               for phase in ("investigate_ms", "resolve_ms")):
            raise Denied("scaled_duration_out_of_bounds")
        return duration_sensitivity(arguments, self.config.get("dependencies", {}), records)

    def evaluate_deadlines(self, arguments):
        from .resilience import audit, closure
        from .recovery_decisions import deadlines
        self.validate("evaluate_recovery_deadlines", arguments)
        records = self.resilience_inputs(arguments["scenario"])
        selected = set(closure(arguments["scenario"]["record_id"], self.config.get("dependencies", {})))
        targets = [row["record_id"] for row in arguments["deadlines"]]
        if len(set(targets)) != len(targets) or not set(targets) <= selected:
            raise Denied("deadline_targets_denied")
        if not audit(arguments["scenario"], self.config.get("dependencies", {}), records, arguments["trace"])["valid"]:
            raise Denied("recovery_trace_invalid")
        return deadlines(arguments["trace"], arguments["deadlines"])

    def validate_trace(self, arguments):
        from .resilience import audit
        self.validate("validate_recovery_trace", arguments)
        records = self.resilience_inputs(arguments["scenario"])
        return audit(arguments["scenario"], self.config.get("dependencies", {}), records, arguments["trace"])

    def resilience_inputs(self, arguments):
        records = self.validate("simulate_recovery_resilience", arguments)
        selected = {step["record"]["id"] for step in self.store._resolution_steps(arguments["record_id"], records, self.hardened)}
        durations = [row["record_id"] for row in arguments["durations"]]
        faults = [(row["record_id"], row["status"]) for row in arguments["faults"]]
        if (len(set(durations)) != len(durations) or not set(durations) <= selected or len(set(faults)) != len(faults)
                or any(key not in selected for key, _ in faults)):
            raise Denied("resilience_overrides_denied")
        if any(row["worker"] >= arguments["max_parallel"] or row["start_ms"] >= row["end_ms"] for row in arguments["worker_outages"]):
            raise Denied("worker_outage_invalid")
        return records

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

    def rank_bottlenecks(self, arguments):
        records = self.validate("rank_dependency_bottlenecks", arguments)
        steps = self.store._resolution_steps(arguments["record_id"], records, self.hardened)
        selected = {step["record"]["id"] for step in steps}
        children = {key: set() for key in selected}
        for child in selected:
            for parent in self.config.get("dependencies", {}).get(child, []):
                children[parent].add(child)
        impacts, depths = {}, {}
        for step in reversed(steps):
            key = step["record"]["id"]
            impacts[key] = {key}.union(*(impacts[child] for child in children[key]))
            depths[key] = max((depths[child] + 1 for child in children[key]), default=0)
        ranking = [{"record_id": key, "impacted_count": len(impacts[key]), "direct_dependents": len(children[key]),
                    "unresolved_dependents": sum(records[child]["status"] != "resolved" for child in impacts[key] - {key}),
                    "downstream_depth": depths[key]} for key in selected]
        ranking.sort(key=lambda row: (-row["impacted_count"], -row["unresolved_dependents"], row["record_id"]))
        return {"record_id": arguments["record_id"], "node_count": len(selected), "ranking": ranking[:arguments["limit"]],
                "snapshot": [copy.deepcopy(records[key]) for key in sorted(selected)]}

    def recovery_timeline(self, arguments):
        records = self.validate("simulate_recovery_timeline", arguments)
        steps = self.store._resolution_steps(arguments["record_id"], records, self.hardened)
        selected = sorted(step["record"]["id"] for step in steps)
        overrides = {row["record_id"]: row for row in arguments["durations"]}
        if len(overrides) != len(arguments["durations"]) or not set(overrides) <= set(selected):
            raise Denied("duration_overrides_denied")
        def duration(key, target):
            return overrides.get(key, {}).get("investigate_ms" if target == "investigating" else "resolve_ms", 1)
        critical = {}
        for step in steps:
            key, record = step["record"]["id"], step["record"]
            critical[key] = (0 if record["status"] == "resolved" else
                max(duration(key, "investigating") if record["status"] == "open" else 0,
                    max((critical[parent] for parent in step["depends_on"]), default=0)) + duration(key, "resolved"))
        proposed = {key: copy.deepcopy(records[key]) for key in selected}
        events, running, active = [], [], set()
        available = list(range(arguments["max_parallel"]))
        now = 0
        while any(record["status"] != "resolved" for record in proposed.values()):
            ready = []
            for key in selected:
                record = proposed[key]
                if key in active or record["status"] == "resolved":
                    continue
                target = "investigating" if record["status"] == "open" else "resolved"
                if target == "investigating" or all(proposed[parent]["status"] == "resolved"
                        for parent in self.config.get("dependencies", {}).get(key, [])):
                    ready.append({"record_id": key, "status": target, "expected_version": record["version"]})
            ready.sort(key=lambda update: (update["status"] != "resolved", update["record_id"]))
            for update in ready[:len(available)]:
                worker = heapq.heappop(available)
                key = update["record_id"]
                end = now + duration(key, update["status"])
                events.append({**update, "worker": worker, "start_ms": now, "end_ms": end})
                heapq.heappush(running, (end, worker, update))
                active.add(key)
            if not running:
                raise Denied("recovery_plan_blocked")
            now = running[0][0]
            # All completions at a timestamp become visible before dispatching
            # any newly released work, including work on another worker.
            while running and running[0][0] == now:
                _, worker, update = heapq.heappop(running)
                key = update["record_id"]
                proposed[key].update(status=update["status"], version=update["expected_version"] + 1)
                active.remove(key)
                heapq.heappush(available, worker)
        work = sum(event["end_ms"] - event["start_ms"] for event in events)
        workers = arguments["max_parallel"]
        return {"record_id": arguments["record_id"], "max_parallel": workers, "events": events,
                "makespan_ms": now, "total_work_ms": work, "critical_path_ms": max(critical.values(), default=0),
                "worker_lower_bound_ms": (work + workers - 1) // workers,
                "snapshot": [copy.deepcopy(records[key]) for key in selected]}
