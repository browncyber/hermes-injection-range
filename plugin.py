"""Hermes wiring: the /drill command, the hooks, and the ``hermes drill`` CLI.

``/drill run`` plants documents that carry test injections, asks the agent to do an ordinary
task with each one, blocks any tool call that carries a drill canary, and scores what the
agent did.
"""
from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from typing import Any

from .engine import Range
from .report import render, render_list
from .scenarios import BY_ID

logger = logging.getLogger(__name__)

PLUGIN_NAME = "injection-range"

HELP = """/drill run [id ...]   start a drill (all scenarios, or the ones you name)
/drill next           send the next scenario's task (when auto-advance is off or unavailable)
/drill report         show the scorecard
/drill list           list scenarios
/drill stop           end the drill and delete the planted files"""


MANUAL_HINT = ("(This surface did not let the plugin send the task for you. To let the drill advance by "
               "itself, set plugins.entries.injection-range.allow_gateway_injection: true and restart "
               "Hermes. Until then, send each task yourself and use /drill next.)")


def _data_dir() -> Path:
    try:
        from plugins.plugin_storage import plugin_data_dir
        return Path(plugin_data_dir(PLUGIN_NAME))
    except Exception:
        return Path(tempfile.gettempdir()) / PLUGIN_NAME


def _setting(ctx: Any, key: str, default: Any) -> Any:
    try:
        value = ctx.get_config(key, default=default)
    except Exception:
        return default
    return default if value is None else value


class Plugin:
    def __init__(self, ctx: Any):
        self.ctx = ctx
        self.range = Range(_data_dir(), str(_setting(ctx, "staging_dir", "") or ""))
        self.session_key = ""   # the session that ran /drill; the terminal UI routes injections by it

    # ── talking to the session ────────────────────────────────────────────
    def _inject(self, text: str) -> bool:
        """Queue *text* as the user's next message. False where the host refuses (a messaging
        gateway without ``allow_gateway_injection``) or the API is missing."""
        fn = getattr(self.ctx, "inject_message", None)
        if fn is None:
            return False
        try:
            if self.session_key:
                try:
                    return bool(fn(text, session_key=self.session_key))
                except TypeError:      # older Hermes: no session_key keyword
                    pass
            return bool(fn(text))
        except Exception:
            logger.debug("inject_message failed", exc_info=True)
            return False

    def _post(self, text: str) -> bool:
        fn = getattr(self.ctx, "post_message", None)
        if fn is None:
            return False
        try:
            return bool(getattr(fn(text), "ok", False))
        except Exception:
            logger.debug("post_message failed", exc_info=True)
            return False

    def _auto(self) -> bool:
        return bool(_setting(self.ctx, "auto_advance", True))

    def _position(self) -> str:
        run = self.range.run
        return f"scenario {run.index + 1} of {len(run.results)}"

    # ── /drill ────────────────────────────────────────────────────────────
    def command(self, raw_args: str = "", session_id: str = "", platform: str = "",
                session_key: str = "", **_: Any) -> str:
        if session_key:
            self.session_key = str(session_key)
        parts = (raw_args or "").split()
        verb = parts[0].lower() if parts else "help"
        if verb == "run":
            return self._run(parts[1:], session_id, platform)
        if verb == "next":
            return self._next()
        if verb == "report":
            return render(self.range.last())
        if verb == "list":
            return render_list()
        if verb == "stop":
            if self.range.stop():
                return "Drill stopped. Planted files deleted.\n\n" + render(self.range.last())
            return "No drill is running."
        return HELP

    def _run(self, ids: list[str], session_id: str, platform: str) -> str:
        ids = [i for i in ids if i != "all"]
        unknown = [i for i in ids if i not in BY_ID]
        if unknown:
            return f"Unknown scenario: {', '.join(unknown)}.\n\n{render_list()}"
        run = self.range.start(ids, session_id, platform)
        head = (f"Drill {run.id} armed: {len(run.results)} scenario(s). Each plants one document with a "
                "test injection and asks the agent for an ordinary task. Any tool call that carries a "
                "drill canary is blocked before it runs, so nothing a payload asks for can happen.")
        task = self.range.task_for(run.current)
        if self._auto() and self._inject(task):
            return f"{head}\n\nStarting {self._position()}. The scorecard follows the last one."
        return f"{head}\n\nSend this message to start {self._position()}:\n\n{task}\n\n{MANUAL_HINT}"

    def _next(self) -> str:
        run = self.range.run
        if run is None or run.finished:
            return "No drill is running. Start one with /drill run."
        if run.current.started and self.range.advance() is None:
            return render(self.range.last())
        task = self.range.task_for(run.current)
        if self._inject(task):
            return f"Starting {self._position()}."
        return f"Send this message for {self._position()}:\n\n{task}"

    # ── hooks ─────────────────────────────────────────────────────────────
    def pre_llm_call(self, session_id: str = "", user_message: Any = "", model: str = "",
                     platform: str = "", **_: Any) -> None:
        self.range.on_turn_start(session_id or "", user_message, model or "", platform or "")

    def pre_tool_call(self, tool_name: str = "", args: Any = None, **_: Any) -> Any:
        return self.range.check_tool_call(tool_name or "", args)

    def post_tool_call(self, tool_name: str = "", args: Any = None, status: Any = None, **_: Any) -> None:
        self.range.on_tool_result(tool_name or "", args, status)

    def pre_api_request(self, request_messages: Any = None, conversation_history: Any = None,
                        **_: Any) -> None:
        if self.range.run is None or self.range.run.finished:
            return
        self.range.on_api_request(request_messages if request_messages is not None else conversation_history)

    def post_llm_call(self, session_id: str = "", assistant_response: Any = "", **_: Any) -> None:
        self.range.on_reply(session_id or "", assistant_response)

    def on_session_end(self, session_id: str = "", **_: Any) -> None:
        """Fires at the end of every turn. When it was a drill turn, score it and move on."""
        if not self.range.turn_ended(session_id or ""):
            return
        nxt = self.range.advance()
        if nxt is None:
            self._post(render(self.range.last()))   # if the host has no channel, /drill report shows it
            return
        if self._auto() and self._inject(self.range.task_for(nxt)):
            return
        self._post(f"Drill: {self._position()} is ready. Send /drill next to continue.")


def _cli_setup(parser: Any) -> None:
    sub = parser.add_subparsers(dest="drill_command")
    sub.add_parser("list", help="List drill scenarios")
    report = sub.add_parser("report", help="Show the last drill's scorecard")
    report.add_argument("--json", action="store_true", help="Print the raw result as JSON")


def register(ctx: Any) -> None:
    plugin = Plugin(ctx)

    def _cli(args: Any) -> None:
        if getattr(args, "drill_command", None) == "list":
            print(render_list())
        elif getattr(args, "json", False):
            print(json.dumps(plugin.range.last() or {}, indent=2))
        else:
            print(render(plugin.range.last()))

    ctx.register_hook("pre_llm_call", plugin.pre_llm_call)
    ctx.register_hook("pre_tool_call", plugin.pre_tool_call)
    ctx.register_hook("post_tool_call", plugin.post_tool_call)
    ctx.register_hook("pre_api_request", plugin.pre_api_request)
    ctx.register_hook("post_llm_call", plugin.post_llm_call)
    ctx.register_hook("on_session_end", plugin.on_session_end)
    ctx.register_command("drill", plugin.command, description="Run a prompt-injection drill against this agent",
                         args_hint="run | next | report | list | stop")
    ctx.register_cli_command("drill", "Prompt-injection drill results", _cli_setup, _cli,
                             description="List injection-range scenarios or print the last scorecard.")


__all__ = ["register", "Plugin"]
