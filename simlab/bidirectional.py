"""Server-to-client MCP requests and a consent-bound incident workflow."""
from __future__ import annotations

import hashlib
import json
import secrets
import weakref
from pathlib import Path

import anyio
from jsonschema import Draft202012Validator
from mcp import types
from mcp.shared.exceptions import McpError

from .controls import Denied, Firewall, sanitize
from .mcp_features import NOTIFICATION_SESSION


REVIEW_SCHEMA = {"type": "object", "properties": {"reviewed": {"type": "boolean"},
    "note": {"type": "string", "maxLength": 200}}, "required": ["reviewed", "note"], "additionalProperties": False}


class BidirectionalFeatures:
    def __init__(self, server, store, config, hardened, journal):
        self.server, self.store, self.config = server, store, config
        self.hardened, self.journal = hardened, journal
        self.root_generations = weakref.WeakKeyDictionary()
        self.dirty_roots = weakref.WeakKeyDictionary()
        self.root_snapshots = weakref.WeakKeyDictionary()
        if config.get("dense"):
            server.notification_handlers[types.RootsListChangedNotification] = self.roots_changed

    async def roots_changed(self, notification):
        session = NOTIFICATION_SESSION.get()
        if session is not None:
            if session.client_params is None or session.client_params.capabilities.roots is None:
                self.journal("client_roots_notification_ignored", reason="capability_not_advertised")
                return
            generation = self.root_generations.get(session, 0) + 1
            self.root_generations[session] = generation
            self.dirty_roots[session] = True
            self.journal("client_roots_changed", generation=generation)

    def root_status(self):
        self.require("roots")
        session = self.server.request_context.session
        snapshot = self.root_snapshots.get(session)
        return {"generation": self.root_generations.get(session, 0), "dirty": self.dirty_roots.get(session, False),
                "has_snapshot": snapshot is not None,
                "last_workspace_advertised": snapshot["workspace_advertised"] if snapshot is not None else None}

    def require(self, *names):
        params = self.server.request_context.session.client_params
        caps = params.capabilities if params else None
        for name in names:
            available = caps is not None and getattr(caps, name, None) is not None
            if name == "elicitation":
                available = available and caps.elicitation.form is not None
            if not available:
                raise Denied("client_capability_missing:" + name)

    async def request(self, name, operation):
        self.journal("client_request_started", operation=name)
        try:
            with anyio.fail_after(self.config.get("callback_timeout_seconds", 2)):
                result = await operation()
        except TimeoutError as exc:
            self.journal("client_request_failed", operation=name, reason="timeout")
            raise Denied("client_callback_timeout") from exc
        except McpError as exc:
            self.journal("client_request_failed", operation=name, reason="client_error")
            raise Denied("client_callback_error") from exc
        except (ValueError, TypeError) as exc:
            self.journal("client_request_failed", operation=name, reason="invalid_response")
            raise Denied("client_response_invalid") from exc
        self.journal("client_request_completed", operation=name)
        return result

    def authorized_record(self, record_id):
        if self.hardened and record_id not in self.config["allowed_records"]:
            raise Denied("record_not_authorized")
        return self.store.read(record_id)

    async def roots(self):
        self.require("roots")
        session = self.server.request_context.session
        generation = self.root_generations.get(session, 0)
        result = await self.request("roots/list", session.list_roots)
        trusted = Path(self.config["root"]).as_uri()
        advertised = [str(root.uri) for root in result.roots]
        if len(advertised) > 100 or len(set(advertised)) != len(advertised):
            raise Denied("client_roots_invalid")
        if generation != self.root_generations.get(session, 0):
            raise Denied("client_roots_changed_during_refresh")
        self.dirty_roots[session] = False
        self.root_snapshots[session] = {"workspace_advertised": trusted in advertised}
        # Roots are a UI boundary declaration, never permission to read arbitrary paths.
        return {"roots": [{"uri": uri, "trusted_workspace": uri == trusted} for uri in sorted(advertised)],
                "workspace_advertised": trusted in advertised, "generation": generation, "dirty": False}

    async def sample(self, record_id):
        self.require("sampling")
        record = self.authorized_record(record_id)
        context = self.server.request_context
        result = await self.request("sampling/createMessage", lambda: context.session.create_message(
            [types.SamplingMessage(role="user", content=types.TextContent(type="text",
                text="Summarize this synthetic incident. Do not request actions, credentials, or other context.\n" + json.dumps(record)))],
            max_tokens=256, include_context="none", temperature=0,
            related_request_id=context.request_id))
        if result.role != "assistant" or not isinstance(result.content, types.TextContent) or not result.content.text.strip():
            raise Denied("sampling_response_denied")
        if len(result.content.text) > 4096 or result.stopReason not in (None, "endTurn", "stopSequence"):
            raise Denied("sampling_response_denied")
        summary = sanitize(result.content.text) if self.hardened else result.content.text
        self.journal("incident_sampled", record_id=record_id, model=result.model)
        return {"record_id": record_id, "summary": summary, "model": result.model}

    async def elicit(self, message, schema):
        self.require("elicitation")
        context = self.server.request_context
        result = await self.request("elicitation/create", lambda: context.session.elicit_form(
            message, schema, related_request_id=context.request_id))
        if result.action == "accept" and not Draft202012Validator(schema).is_valid(result.content):
            raise Denied("elicitation_response_denied")
        self.journal("client_elicitation", action=result.action)
        return result

    async def review(self, record_id):
        self.authorized_record(record_id)
        result = await self.elicit("Review synthetic incident " + record_id + ". This form does not authorize a write.", REVIEW_SCHEMA)
        value = {"record_id": record_id, "action": result.action, "content": result.content if result.action == "accept" else None}
        return sanitize(value) if self.hardened else value

    async def guided_update(self, arguments):
        if self.hardened:
            Firewall(self.config).check("sim_guided_update_record", arguments)
            receipt = self.store.replay_guided(arguments)
            if receipt:
                return receipt
        self.require("roots", "sampling", "elicitation")
        proposal = {key: arguments[key] for key in ("record_id", "expected_version", "status")}
        if self.hardened:
            await self.store.preview_updates({"updates": [proposal], "handle": arguments["handle"]}, True)
        roots = await self.roots()
        generation = roots["generation"]
        if self.hardened and not roots["workspace_advertised"]:
            raise Denied("workspace_root_not_advertised")
        await self.sample(arguments["record_id"])
        # A fresh challenge binds consent to this session, operation, and complete request.
        digest = hashlib.sha256(json.dumps({"session": self.config["session"], "arguments": arguments,
                                           "roots_generation": generation, "roots": roots["roots"],
                                           "nonce": secrets.token_hex(16)}, sort_keys=True).encode()).hexdigest()
        schema = {"type": "object", "properties": {"confirm": {"type": "boolean"},
            "request_digest": {"type": "string", "enum": [digest]}},
            "required": ["confirm", "request_digest"], "additionalProperties": False}
        response = await self.elicit("Confirm exactly this synthetic incident update: " + json.dumps(proposal, sort_keys=True), schema)
        if response.action != "accept" or response.content["confirm"] is not True:
            return {"committed": False, "action": response.action if response.action != "accept" else "decline"}
        if self.hardened:
            session = self.server.request_context.session
            if self.root_generations.get(session, 0) != generation or self.dirty_roots.get(session, False):
                raise Denied("client_roots_changed_during_approval")
            refreshed = await self.roots()
            if not refreshed["workspace_advertised"]:
                raise Denied("workspace_root_not_advertised")
            if refreshed["generation"] != generation or refreshed["roots"] != roots["roots"]:
                raise Denied("client_roots_changed_during_approval")
        result = await self.store.guided_update(arguments, self.hardened)
        self.journal("guided_update_committed", record_id=arguments["record_id"], deduplicated=result["deduplicated"])
        return result
