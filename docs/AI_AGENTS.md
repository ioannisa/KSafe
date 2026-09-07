# KSafe Skill for AI Agents

Installing the KSafe skill into Claude Code and every other agent, keeping it up to date, and the one mistake that silently loads a stale copy.

***

KSafe ships an [agentskills.io](https://agentskills.io)-compatible skill — [**skills/ksafe/SKILL.md**](../skills/ksafe/SKILL.md) — that teaches any AI agent (Claude Code, Codex, Gemini CLI, Copilot CLI, Junie) KSafe's patterns, anti-patterns, and gotchas. Restart your agent session after installing — skills load at session start.

### Claude Code (recommended)
> installs once, updates itself

Run **both** commands, in this order, inside any Claude Code session. It's a one-time setup:

```
/plugin marketplace add ioannisa/KSafe    # 1. register this repo as a plugin source
/plugin install ksafe@ksafe               # 2. install the ksafe skill from it
```

The first command only tells Claude Code where the plugin lives — it installs nothing by
itself. The second does the actual install (the format is `<plugin>@<marketplace>`; both
happen to be named `ksafe` here). Restart the session and the skill is active.

From then on updates are handled for you — but on Claude Code's own schedule, not at the
moment we publish. If you want the newest skill *now* (say, right after a KSafe release),
force it; see below.

<details>
<summary><b>Forcing an update — and why one command isn't always enough</b></summary>

An installed plugin is pinned to a specific commit of this repo, and Claude Code keeps its
own clone of the repo separately. So there are **two** things that can be out of date, and
refreshing only the second one silently does nothing:

| Layer | What it is | Refreshed by |
|---|---|---|
| **Marketplace** | Claude Code's clone of this repo | `marketplace update` |
| **Plugin** | the commit your session actually loads | `update` |

Run them **in this order** — the plugin can only move to a commit the marketplace has
already fetched:

```
/plugin marketplace update ksafe    # 1. fetch the newest commits of this repo
/plugin update ksafe@ksafe          # 2. re-pin the plugin to the newest one
```

Same thing from a terminal, outside any session:

```bash
claude plugin marketplace update ksafe
claude plugin update ksafe@ksafe
```

**Restart the session afterwards** — a running session keeps the skill it loaded at start.

Check what you're actually on at any time:

```bash
claude plugin list
```

The `Version:` shown for `ksafe@ksafe` is the commit hash this repo was at when the plugin
was pinned. If step 2 reports *"already at the latest version"* but you expected something
newer, step 1 hasn't picked up the commit yet — the release may not be pushed, or the
marketplace fetch failed.

</details>

> **Don't also copy `SKILL.md` into `~/.claude/skills/ksafe/`.** That directory holds
> manually-installed skills, which never update and are addressed by the bare name `ksafe`
> — while the plugin is addressed as `ksafe:ksafe`. Keeping both means asking for "the
> ksafe skill" loads the stale hand-copied one. Pick the plugin *or* the plain copy below,
> never both.

### Other agents
> (Codex, Gemini CLI, Copilot, Cursor, Junie, …)
> pick ONE of the two options below

**Option A — the [skills.sh](https://skills.sh) CLI (recommended):** one command installs the
skill into whichever of your agents you select in its prompt (30+ supported):

```bash
npx skills add ioannisa/KSafe
```

There is no auto-update for these agents — re-run the same command whenever you want the
latest skill (e.g. after a KSafe release).

**Option B — plain copy, no tooling:** fetch the file straight into each agent's skills
directory. Edit the agent list to match what you actually use:

```bash
for agent in codex gemini copilot junie; do
  mkdir -p "$HOME/.$agent/skills/ksafe" && \
    curl -fsSL https://raw.githubusercontent.com/ioannisa/KSafe/main/skills/ksafe/SKILL.md \
    > "$HOME/.$agent/skills/ksafe/SKILL.md"
done
```

Re-run it to refresh (again: no auto-update). If you've already cloned this repo,
`cp -r skills/ksafe "$HOME/.<agent>/skills/"` does the same thing offline. Add `claude` to
the list only if you prefer a plain skill over the plugin from the section above — for the
reason why the two don't mix, see the warning at the end of that section.
