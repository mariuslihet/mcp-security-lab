"""Bounded, reproducible DAG fixtures and independent graph validation."""
from __future__ import annotations

import random
import re


def validate_graph(graph: dict) -> list[list[str]]:
    if not isinstance(graph, dict) or not 4 <= len(graph) <= 128:
        raise ValueError("dependency graph requires 4 to 128 nodes")
    if any(not isinstance(key, str) or not re.fullmatch(r"GR-[0-9]{3}", key) for key in graph):
        raise ValueError("invalid dependency graph identifier")
    for key, parents in graph.items():
        if (not isinstance(parents, list) or len(parents) > 8 or any(not isinstance(parent, str) for parent in parents)
                or len(set(parents)) != len(parents) or any(parent not in graph or parent == key for parent in parents)):
            raise ValueError("invalid dependency graph edge")
    remaining, layers = set(graph), []
    while remaining:
        ready = sorted(key for key in remaining if not (set(graph[key]) & remaining))
        if not ready:
            raise ValueError("dependency graph contains a cycle")
        layers.append(ready)
        remaining.difference_update(ready)
    return layers


def generate_graph(seed: int, nodes: int = 32, width: int = 4) -> dict:
    if type(seed) is not int or type(nodes) is not int or type(width) is not int or not 8 <= nodes <= 128 or not 2 <= width <= 8 or width >= nodes:
        raise ValueError("generated graphs require 8 to 128 nodes and width 2 to 8")
    rng, graph = random.Random(seed), {}
    for index in range(nodes):
        layer = index // width
        if layer == 0:
            parents = []
        else:
            previous = [f"GR-{i:03}" for i in range((layer - 1) * width, layer * width)]
            # Full previous-layer fan-in creates shared prerequisites and reconvergent paths.
            parents = list(previous)
            older = [key for key in graph if int(key.split("-")[1]) < (layer - 1) * width]
            if older and len(parents) < 8:
                parents += rng.sample(older, min(8 - len(parents), rng.randint(0, 2), len(older)))
            rng.shuffle(parents)
        graph[f"GR-{index:03}"] = parents
    validate_graph(graph)
    return graph
