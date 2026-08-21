# Apply Receipt

> Generated at the end of the apply phase to mark code-implementation
> complete and provide verify with the state it needs.
> Overwritten on each apply iteration; iteration counter grows.

**Change**: `<change-name>`
**Iteration**: `1`
**Applied at**: `YYYY-MM-DD HH:mm`
**Executor**: `subagent-driven-development` | `executing-plans`

---

## Workspace

- **Worktree**: `.worktrees/<change-name>/`
- **Branch**: `<branch-name>`

---

## Commits

- **Range**: `<from-sha>..<to-sha>` (or `none` if nothing committed yet)
- **Count**: `<n>`

---

## Tasks

- **Completed**: `X of Y` checkboxes in tasks.md flipped to `- [x]`
- **Remaining**: `<list ids of unfinished tasks, or "none">`

---

## Next step

`<e.g., "Run /opsx:verify" or "Re-run apply to address <issue>">`
