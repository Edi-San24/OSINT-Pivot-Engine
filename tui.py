# tui.py
# Textual interface for the OSINT Pivot Engine.
#
# Launched by main.py when no CLI arguments are given. The Click CLI stays the
# non-interactive path and the MCP server is untouched; all three drive the
# same core.agent.run_agent.
#
# The engine is imported lazily. Constructing PivotExecutor loads the MITRE
# ATT&CK STIX bundle and builds the NER table, several seconds during which a
# terminal app would look frozen, so the UI paints first and loads after.

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path

from rich.console import Group
from rich.panel import Panel
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    RichLog,
    Select,
    Checkbox,
    Static,
)

from config import ENV_PATH, PROJECT_ROOT
from core.render import build_metrics_table, format_summary, get_risk_color
from core.risk import extract_dissent, extract_threat_level, resolve_risk_level

ACCENT = "#17375E"

# Derived from ACCENT rather than picked separately, so the scheme stays one
# colour. BORDER is the accent lifted until it reads against the background:
# #17375E on #0b1220 is nearly invisible as a one-cell line, which is why every
# panel edge used to disappear. GLOW is for focus and the active spinner.
SURFACE = "#0e1728"
BORDER = "#2b537f"
GLOW = "#5b9bd5"
MUTED = "#7d8ba3"
HISTORY_PATH = PROJECT_ROOT / ".tui_history.json"
HISTORY_LIMIT = 10

# MEDIUM abbreviates in the dissent position only. The sidebar leaves 38
# columns, and the widest row this can produce, UNKNOWN>HIGH, has to fit
# beside a readable seed.
DISSENT_ABBREV = {"HIGH": "HIGH", "MEDIUM": "MED", "LOW": "LOW", "UNKNOWN": "UNK"}

# Ten frames at a 0.1s interval gives exactly one revolution per second.
SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


# Credentials the wizard collects. SpiderFoot is a self-hosted URL rather than
# a key, and MalwareBazaar shares abuse.ch's THREATFOX_API_KEY, so the label
# and the variable deliberately differ.
CREDENTIALS = [
    ("VIRUSTOTAL_API_KEY", "VirusTotal", True,
     "Detection consensus and file reputation.", "virustotal.com/gui/join-us"),
    ("THREATFOX_API_KEY", "MalwareBazaar / abuse.ch", True,
     "Malware samples and family clustering. One key covers all abuse.ch services.",
     "auth.abuse.ch"),
    ("OTX_API_KEY", "AlienVault OTX", True,
     "Community pulse intelligence and sector targeting.", "otx.alienvault.com"),
    ("ANTHROPIC_API_KEY", "Anthropic", False,
     "Writes the analyst summary. Without it everything else still runs.",
     "console.anthropic.com"),
    ("SHODAN_API_KEY", "Shodan", False,
     "Open ports, banners, hosting details.", "account.shodan.io"),
    ("CENSYS_API_KEY", "Censys", False,
     "Certificate transparency and geolocation.", "search.censys.io/account/api"),
    ("SPIDERFOOT_URL", "SpiderFoot URL", False,
     "Self-hosted instance for email and username pivots. Not a key.",
     "default http://127.0.0.1:5001"),
]

REQUIRED_KEYS = [name for name, _, required, _, _ in CREDENTIALS if required]


def read_env(path: str = ENV_PATH) -> dict:
    """Parses .env into a dict. Missing file yields an empty dict."""
    values = {}
    try:
        for line in Path(path).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return values


def write_env(values: dict, path: str = ENV_PATH) -> None:
    """
    Writes .env, preserving any keys already there that the wizard did not ask
    about, so an existing file is never silently truncated.
    """
    merged = read_env(path)
    merged.update({k: v for k, v in values.items() if v})

    known = [name for name, _, _, _, _ in CREDENTIALS]
    lines = ["# Written by the OSINT Pivot Engine setup wizard.", ""]
    for name in known:
        if name in merged:
            lines.append(f"{name}={merged[name]}")
    extras = sorted(set(merged) - set(known))
    if extras:
        lines += ["", "# Other values already present"]
        lines += [f"{name}={merged[name]}" for name in extras]
    Path(path).write_text("\n".join(lines) + "\n")


def setup_needed() -> bool:
    """True when .env is absent or any required credential is blank."""
    values = read_env()
    return any(not values.get(key) for key in REQUIRED_KEYS)


def load_history() -> list:
    try:
        data = json.loads(HISTORY_PATH.read_text())
        return data if isinstance(data, list) else []
    except Exception:
        return []


def save_history(entries: list) -> None:
    try:
        HISTORY_PATH.write_text(json.dumps(entries[:HISTORY_LIMIT], indent=2, default=str))
    except Exception:
        pass  # History is a convenience; never let it break an investigation.


def entry_level(entry: dict) -> str:
    """
    The level a history row shows, re-derived rather than read back.

    The stored risk_level is a cache of a derivation, and it went stale when the
    verdict stopped coming from the agent: entries saved while an override was
    possible listed one level and opened at another. The detail view already
    re-derives, so deriving here too is what makes the two agree.
    """
    result = entry.get("result")
    if not isinstance(result, dict) or "context_score" not in result:
        # Saved before results were kept inline. The cache is all there is.
        return entry.get("risk_level", "UNKNOWN")
    return resolve_risk_level(result)


def entry_agent_level(entry: dict) -> str | None:
    """
    What the agent read, when it differs from the row's verdict. None otherwise.

    Two eras of saved entry answer this differently. A run since the verdict
    became deterministic states its own read on a DISSENT line. An older one
    put it on the THREAT LEVEL line, because back then that line was the
    agent's and it was what decided the level.
    """
    result = entry.get("result")
    if not isinstance(result, dict):
        return None

    summary = result.get("summary", "")
    dissent = extract_dissent(summary)
    if dissent:
        return dissent

    # Pre-deterministic entry: the stated level is the agent's own only when it
    # disagrees with the score, which is exactly the override case.
    stated = extract_threat_level(summary)
    if stated and stated != entry_level(entry):
        return stated
    return None


def discovered_indicators(result: dict) -> list[tuple[str, str]]:
    """
    Pulls everything pivotable out of a completed investigation, so following
    a lead is a keypress instead of select, copy, paste.

    Anything already visited is skipped: re-running the seed you just ran is
    never what you meant.
    """
    visited = {v.lower() for v in result.get("visited", [])}
    found: dict[str, str] = {}

    def add(kind: str, value: str) -> None:
        value = (value or "").strip()
        if value and value != "unknown" and value.lower() not in visited:
            found.setdefault(value, kind)

    for pivot in result.get("full_results", []):
        results = pivot.get("results", {})

        for record in results.get("passivedns", {}).get("records", []):
            add("ip", record.get("ip", ""))
            add("domain", record.get("domain", ""))

        for cert in results.get("censys", {}).get("certificates", []):
            for name in (cert.get("names", "") or "").replace("\n", ",").split(","):
                add("domain", name.strip().lstrip("*."))

        for key in ("malwarebazaar", "malwarebazaar_related"):
            for sample in results.get(key, {}).get("samples", []) or []:
                add("hash", sample.get("sha256", ""))

        for group in results.get("mitre", {}).get("groups", []) or []:
            add("group", group.get("name", ""))
        for software in results.get("mitre", {}).get("software", []) or []:
            add("malware", software.get("name", ""))

        for entry in results.get("malwarebazaar_tooling", {}).values():
            if isinstance(entry, dict):
                for sample in entry.get("samples", []) or []:
                    add("hash", sample.get("sha256", ""))

    order = {"hash": 0, "domain": 1, "ip": 2, "malware": 3, "group": 4}
    return sorted(
        ((kind, value) for value, kind in found.items()),
        key=lambda pair: (order.get(pair[0], 9), pair[1]),
    )


class IndicatorPicker(ModalScreen[str | None]):
    """Pick a discovered indicator and load it into the seed field."""

    BINDINGS = [Binding("escape", "dismiss_none", "Cancel")]

    def __init__(self, indicators: list[tuple[str, str]]) -> None:
        super().__init__()
        self.indicators = indicators[:40]

    def compose(self) -> ComposeResult:
        with Vertical(id="picker"):
            yield Label(f"[bold]Pivot from this result[/bold]  "
                        f"[dim]{len(self.indicators)} indicators[/dim]")
            yield ListView(*[
                ListItem(Static(f"[dim]{kind:<8}[/dim]{value}"))
                for kind, value in self.indicators
            ], id="picker-list")
            yield Label("[dim]Enter to load into the seed field, Escape to cancel[/dim]")

    def on_mount(self) -> None:
        self.query_one("#picker-list", ListView).focus()

    @on(ListView.Selected, "#picker-list")
    def _chosen(self, event: ListView.Selected) -> None:
        index = event.list_view.index
        if index is not None and index < len(self.indicators):
            self.dismiss(self.indicators[index][1])
        else:
            self.dismiss(None)

    def action_dismiss_none(self) -> None:
        self.dismiss(None)


class SetupScreen(Screen):
    """
    First-run wizard. Walks the credential list one at a time rather than
    showing one big form, so it is obvious which are required and what each
    one buys you.
    """

    BINDINGS = [Binding("escape", "quit_app", "Quit")]

    def __init__(self) -> None:
        super().__init__()
        self.index = 0
        self.collected: dict = {}
        self.existing = read_env()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Vertical(id="wizard"):
            yield Static("", id="wizard-progress")
            yield Static("", id="wizard-title")
            yield Static("", id="wizard-detail")
            yield Input(placeholder="paste value, or leave blank to skip", id="wizard-input")
            yield Static("", id="wizard-warning")
            with Horizontal(id="wizard-buttons"):
                yield Button("Save and continue", variant="primary", id="wizard-next")
                yield Button("Skip", id="wizard-skip")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "OSINT Pivot Engine"
        self.sub_title = "First run setup"
        self._render_step()

    def _render_step(self) -> None:
        name, label, required, detail, where = CREDENTIALS[self.index]
        tag = "[bold red]REQUIRED[/bold red]" if required else "[dim]optional[/dim]"

        self.query_one("#wizard-progress", Static).update(
            f"[dim]Step {self.index + 1} of {len(CREDENTIALS)}[/dim]"
        )
        self.query_one("#wizard-title", Static).update(f"[bold]{label}[/bold]   {tag}")
        self.query_one("#wizard-detail", Static).update(
            f"{detail}\n[dim]{where}[/dim]"
        )

        field = self.query_one("#wizard-input", Input)
        current = self.collected.get(name) or self.existing.get(name, "")
        field.value = current
        # Only the SpiderFoot URL is meaningful to read back; keys stay masked.
        field.password = name != "SPIDERFOOT_URL"
        field.focus()

        self.query_one("#wizard-skip", Button).label = "Skip" if not required else "Skip anyway"
        self.query_one("#wizard-warning", Static).update("")

    def _advance(self, store: bool) -> None:
        name, label, required, _, _ = CREDENTIALS[self.index]
        value = self.query_one("#wizard-input", Input).value.strip()

        if store and value:
            self.collected[name] = value
        elif required and not (value or self.existing.get(name)):
            self.query_one("#wizard-warning", Static).update(
                f"[yellow]{label} is required. Skipping it means those lookups "
                f"will fail. Press Skip anyway to continue regardless.[/yellow]"
            )
            if store:
                return

        self.index += 1
        if self.index >= len(CREDENTIALS):
            write_env(self.collected)
            self.app.notify("Saved to .env", severity="information")
            self.app.switch_screen(MainScreen())
        else:
            self._render_step()

    @on(Button.Pressed, "#wizard-next")
    def _next(self) -> None:
        self._advance(store=True)

    @on(Button.Pressed, "#wizard-skip")
    def _skip(self) -> None:
        self._advance(store=False)

    @on(Input.Submitted, "#wizard-input")
    def _submitted(self) -> None:
        self._advance(store=True)

    def action_quit_app(self) -> None:
        self.app.exit()


class MainScreen(Screen):
    """Input and history on the left, results on the right."""

    BINDINGS = [
        Binding("q", "quit_app", "Quit"),
        Binding("escape", "quit_app", "Quit"),
        # Drag-select works out of the box, but Textual binds ctrl+c to quit,
        # so copying a selection needs a key of its own.
        Binding("ctrl+shift+c", "copy_text", "Copy selection"),
        Binding("ctrl+a", "select_all_results", "Select all"),
        Binding("ctrl+p", "pick_indicator", "Pivot from result"),
        Binding("ctrl+l", "clear_results", "Clear"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.history = load_history()
        self.results_cache: dict = {}
        self.current_result: dict | None = None
        self.started_at: float | None = None
        self._ticks = 0
        self._timer = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="body"):
            with Vertical(id="sidebar"):
                with Vertical(id="input-panel"):
                    yield Input(
                        placeholder="IP, domain, hash, group, malware family",
                        id="seed",
                    )
                    yield Label("[dim]Pivot depth[/dim]")
                    yield Select(
                        [(f"{n} pivots", n) for n in (1, 2, 3, 5, 8, 10)],
                        value=3,
                        allow_blank=False,
                        id="depth",
                    )
                    # Checkbox rather than Switch: the glyph and its label are
                    # one widget on one row, and an X reads unambiguously where
                    # a borderless slider does not say which end is set.
                    yield Checkbox("Deep scan (SpiderFoot)", id="deep")
                    yield Checkbox("Export STIX 2.1", id="stix")
                    yield Checkbox("Save full JSON", id="save-json")
                    yield Checkbox("Show derivation", id="verbose")
                    yield Button("Run investigation", variant="primary", id="run")
                    yield Static("", id="status")
                with Vertical(id="history-panel"):
                    yield ListView(id="history")
            with Vertical(id="results-panel"):
                # auto_scroll off so a fresh result reads from the top rather
                # than jumping to the end of the summary. min_width matters:
                # RichLog defaults to 78 and the panel's inner width here is
                # about 69, so every summary was rendered nine columns too wide
                # and silently clipped behind a horizontal scrollbar.
                yield RichLog(id="results", wrap=True, markup=True,
                              highlight=False, auto_scroll=False, min_width=20)
        yield Footer()

    def on_mount(self) -> None:
        self.title = "OSINT Pivot Engine"
        self.sub_title = "Autonomous threat intelligence"
        # Titles ride the panel borders rather than costing a row each.
        self.query_one("#input-panel").border_title = "Investigate"
        self.query_one("#history-panel").border_title = "Recent"
        self.query_one("#results-panel").border_title = "Results"
        self._refresh_history()
        self.query_one("#seed", Input).focus()
        log = self.query_one("#results", RichLog)
        log.write(Text("Enter an indicator and press Enter.\n", style="dim"))
        log.write(Text("IP, domain, MD5/SHA1/SHA256, threat group, malware family, "
                       "email, or username.\n", style="dim"))

    # ------------------------------------------------------------------ history

    def _refresh_history(self) -> None:
        view = self.query_one("#history", ListView)
        view.clear()
        for entry in self.history[:HISTORY_LIMIT]:
            level = entry_level(entry)
            agent = entry_agent_level(entry)
            colour = get_risk_color(level).replace("bold ", "")
            seed = entry.get("seed", "")

            # The verdict, then the agent's read beside it when the two differ.
            # Padding is measured on the plain text, since the markup around it
            # does not occupy columns.
            verdict = f"[{colour}]{level}[/{colour}]"
            if agent:
                short = DISSENT_ABBREV.get(agent, agent)
                tint = get_risk_color(agent).replace("bold ", "")
                plain = f"{level}>{short}"
                verdict += f"[{tint}]>{short}[/{tint}]"
            else:
                plain = level
            verdict += " " * max(1, 13 - len(plain))

            # One line per entry. Two-line entries clipped in a short panel and
            # cost twice the rows for information that fits on one.
            display = seed if len(seed) <= 15 else seed[:12] + "..."
            view.append(
                ListItem(
                    Static(
                        f"{verdict}{display:<16}"
                        f"[dim]{entry.get('when','')[-5:]}[/dim]"
                    )
                )
            )

    @on(ListView.Selected, "#history")
    def _reload(self, event: ListView.Selected) -> None:
        index = event.list_view.index
        if index is None or index >= len(self.history):
            return
        seed = self.history[index].get("seed", "")
        cached = self.results_cache.get(seed.lower()) or self.history[index].get("result")
        if cached:
            self._render_result(cached, replayed=True)
        else:
            self.notify(f"No cached result for {seed}. Run it again.", severity="warning")

    # -------------------------------------------------------------- investigate

    @on(Input.Submitted, "#seed")
    @on(Button.Pressed, "#run")
    def _submit(self) -> None:
        seed = self.query_one("#seed", Input).value.strip()
        if not seed:
            self.notify("Enter an indicator first.", severity="warning")
            return
        if self.started_at is not None:
            self.notify("An investigation is already running.", severity="warning")
            return

        depth = self.query_one("#depth", Select).value
        deep = self.query_one("#deep", Checkbox).value

        self.started_at = time.monotonic()
        self._ticks = 0
        self.query_one("#run", Button).disabled = True
        self._timer = self.set_interval(0.1, self._tick)

        log = self.query_one("#results", RichLog)
        log.clear()
        log.write(Text(f"Investigating {seed}\n", style=f"bold {ACCENT}"))

        self._investigate(seed, int(depth), deep)

    def _tick(self) -> None:
        if self.started_at is None:
            return
        # Frame advances once per tick rather than off elapsed time. Deriving
        # it from the clock meant the frame rate and the timer interval
        # disagreed, so frames repeated and skipped unevenly.
        self._ticks += 1
        frame = SPINNER[self._ticks % len(SPINNER)]
        elapsed = time.monotonic() - self.started_at
        self.query_one("#status", Static).update(
            f"[{ACCENT}]{frame}[/{ACCENT}] running  [dim]{elapsed:5.1f}s[/dim]"
        )

    @work(thread=True, exclusive=True)
    def _investigate(self, seed: str, depth: int, deep: bool) -> None:
        """
        Runs the engine off the UI thread. run_agent blocks for 20-40 seconds,
        which would freeze the interface entirely if run inline.
        """
        try:
            import config
            from core.agent import run_agent

            original_depth = config.MAX_PIVOT_DEPTH
            try:
                config.MAX_PIVOT_DEPTH = depth
                result = run_agent(seed, deep=deep)
            finally:
                config.MAX_PIVOT_DEPTH = original_depth

            self.app.call_from_thread(self._finish, seed, result, None)
        except Exception as exc:
            self.app.call_from_thread(self._finish, seed, None, exc)

    def _finish(self, seed: str, result: dict | None, error: Exception | None) -> None:
        if self._timer:
            self._timer.stop()
            self._timer = None
        elapsed = time.monotonic() - (self.started_at or time.monotonic())
        self.started_at = None
        self.query_one("#run", Button).disabled = False

        if error is not None or result is None:
            self.query_one("#status", Static).update("[red]failed[/red]")
            self.query_one("#results", RichLog).write(
                Panel(Text(f"{type(error).__name__}: {error}", style="red"),
                      title="Investigation failed", border_style="red")
            )
            return

        self.query_one("#status", Static).update(f"[green]done[/green]  [dim]{elapsed:.1f}s[/dim]")
        self._write_optional_files(seed, result)
        self._render_result(result)
        self._record(seed, result)

    def _write_optional_files(self, seed: str, result: dict) -> None:
        safe = "".join(c if c.isalnum() or c in "-._" else "_" for c in seed)[:60]
        log = self.query_one("#results", RichLog)

        if self.query_one("#save-json", Checkbox).value:
            path = PROJECT_ROOT / f"{safe}_results.json"
            path.write_text(json.dumps(result, indent=2, default=str))
            log.write(Text(f"Saved {path.name}", style="green"))

        if self.query_one("#stix", Checkbox).value:
            from core.stix_exporter import STIXExporter
            path = STIXExporter().export(result, str(PROJECT_ROOT / f"{safe}_stix.json"))
            log.write(Text(f"STIX bundle: {Path(path).name}" if path
                           else "STIX export failed", style="green" if path else "red"))

    @on(Checkbox.Changed, "#verbose")
    def _toggle_derivation(self) -> None:
        """Re-render the result in place so verbose can be decided after the fact."""
        if self.current_result is not None:
            self._render_result(self.current_result, replayed=True)

    def _render_result(self, result: dict, replayed: bool = False) -> None:
        self.current_result = result
        log = self.query_one("#results", RichLog)
        if replayed:
            log.clear()

        risk = resolve_risk_level(result)
        log.write(build_metrics_table(result, verbose=self.query_one("#verbose", Checkbox).value))
        log.write(
            Panel(
                Group(format_summary(result.get("summary", ""))),
                title="Investigation Summary",
                border_style=get_risk_color(risk).replace("bold ", ""),
                padding=(1, 2),
            )
        )

    def _record(self, seed: str, result: dict) -> None:
        # Keyed case-insensitively so re-running an indicator with different
        # capitalisation replaces its history entry rather than sitting beside
        # it as a second, identical-looking row.
        self.results_cache[seed.lower()] = result
        self.history = [
            h for h in self.history
            if h.get("seed", "").lower() != seed.lower()
        ]
        self.history.insert(0, {
            "seed": seed,
            "risk_level": resolve_risk_level(result),
            "when": datetime.now().strftime("%b %d %H:%M"),
            # Enough to redisplay without re-running; raw pivots are dropped.
            "result": {k: v for k, v in result.items() if k != "full_results"},
        })
        self.history = self.history[:HISTORY_LIMIT]
        save_history(self.history)
        self._refresh_history()

    # ------------------------------------------------------------------ actions

    def action_select_all_results(self) -> None:
        self.query_one("#results", RichLog).text_select_all()

    def action_pick_indicator(self) -> None:
        """Pull pivotable indicators out of the last result and offer them."""
        if self.current_result is None:
            self.notify("Run an investigation first.", severity="warning")
            return
        found = discovered_indicators(self.current_result)
        if not found:
            self.notify(
                "No pivotable indicators in this result. Replayed history "
                "entries do not keep raw connector output.",
                severity="warning",
            )
            return
        self.app.push_screen(IndicatorPicker(found), self._seed_from_picker)

    def _seed_from_picker(self, chosen: str | None) -> None:
        if chosen:
            self.query_one("#seed", Input).value = chosen
            self.query_one("#seed", Input).focus()

    def action_clear_results(self) -> None:
        self.query_one("#results", RichLog).clear()

    def action_quit_app(self) -> None:
        self.app.exit()


class OsintPivotTUI(App):
    CSS = f"""
    Screen {{ background: #0b1220; }}

    Header {{ background: {ACCENT}; color: white; text-style: bold; }}
    Footer {{ background: {ACCENT}; }}
    Footer > .footer--key {{ background: {BORDER}; color: white; }}

    /* Bottom padding is load-bearing: without it the sidebar runs flush
       into the footer and the last history row is clipped in half. */
    #body {{ height: 1fr; padding: 1 1 1 1; }}

    /* 44 fits "Deep scan (SpiderFoot)" without truncating. */
    #sidebar {{ width: 44; min-width: 38; }}

    /* One panel treatment, three panels. Titles ride the border, which is why
       the header rows inside each panel could go. */
    #input-panel, #history-panel, #results-panel {{
        border: round {BORDER};
        border-title-color: {GLOW};
        border-title-style: bold;
        background: {SURFACE};
        padding: 1 2;
    }}
    #input-panel {{ height: auto; }}
    #history-panel {{ height: 1fr; min-height: 12; margin-top: 1; }}
    #results-panel {{ width: 1fr; margin-left: 1; }}

    #results {{ height: 1fr; background: {SURFACE}; scrollbar-size-vertical: 1; }}
    #history {{ background: {SURFACE}; scrollbar-size-vertical: 1; }}

    #seed {{
        margin-bottom: 1;
        background: #0b1220;
        border: tall #0b1220;
    }}
    #seed:focus {{ border: tall {GLOW}; }}
    #depth {{ margin-bottom: 1; }}

    /* One row per toggle instead of three. A Switch is height 3 for its
       border, and four cost twelve rows of a thirty-five row sidebar, which
       starved the Recent panel to one visible entry. Stripping the border to
       reclaim them left the slider with no track, so on and off both read as a
       filled block; a Checkbox carries its own glyph and does not. */
    Checkbox {{
        height: 1;
        border: none;
        background: transparent;
        padding: 0;
        margin-bottom: 1;
    }}
    Checkbox:focus {{ background: {ACCENT}; }}
    /* Only the checked state is coloured. Textual hides the unchecked glyph by
       drawing it in the button's own background colour, so setting the colour
       unconditionally made every box render a permanent X. */
    Checkbox > .toggle--button {{ background: #0b1220; }}
    Checkbox.-on > .toggle--button {{ color: {GLOW}; background: #0b1220; }}

    #run {{ width: 100%; margin-top: 1; background: {ACCENT}; color: white; }}
    #run:hover {{ background: {BORDER}; }}
    #status {{ height: 1; margin-top: 1; color: {MUTED}; }}

    ListItem {{ height: 1; padding: 0 1; background: {SURFACE}; }}
    ListItem.--highlight {{ background: {ACCENT}; }}
    ListView:focus > ListItem.--highlight {{ background: {BORDER}; }}

    #picker {{
        border: round {BORDER};
        border-title-color: {GLOW};
        background: {SURFACE};
        padding: 1 2;
        margin: 4 12;
        height: auto;
        max-height: 80%;
    }}
    #picker-list {{ height: auto; max-height: 20; background: {SURFACE}; }}

    #wizard {{
        border: round {BORDER};
        border-title-color: {GLOW};
        background: {SURFACE};
        padding: 2 4;
        margin: 2 8;
        height: auto;
    }}
    #wizard-title {{ margin-top: 1; text-style: bold; }}
    #wizard-detail {{ margin-bottom: 1; color: {MUTED}; }}
    #wizard-warning {{ height: auto; }}
    #wizard-buttons {{ height: 3; margin-top: 1; }}
    #wizard-buttons Button {{ margin-right: 2; }}
    """

    def on_mount(self) -> None:
        self.push_screen(SetupScreen() if setup_needed() else MainScreen())


def launch() -> None:
    OsintPivotTUI().run()


if __name__ == "__main__":
    launch()
