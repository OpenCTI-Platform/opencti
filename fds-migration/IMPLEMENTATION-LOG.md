# Implementation Log — OpenCTI

Append-only session journal — never rewrite a previous entry, only add new
ones at the bottom. One entry per work session: date, what changed, why,
and any friction that should feed back into the process (prompts/scripts
in filigran-design-system).

## Log format

```
### YYYY-MM-DD — <short summary>
- Branch: fds/...
- Changed: <files>
- Friction / process feedback: <none, or what to fix upstream>
```

---

### 2026-08-04 — Left navigation replaced by the design-system `Navbar`
- Branch: fds-navbar (targets `design-system/current`)
- Pin: `56f7e59823cae7d815a451206e3cb4cb1d31022d` (head of the library's `main`)
- Changed:
  - Added `opencti-front/src/private/components/nav/`: `NavBar.tsx`
    (data component + exported pure `NavBarView`), `useNavMenu.tsx` (typed,
    fully filtered menu tree + pure `filterNavGroups`), `navBarConstants.ts`
    (rail widths, storage keys, persistence helpers), and their tests.
  - Deleted `LeftBar.jsx`, `LeftBarItem.tsx`, `LeftBarHeader.tsx`.
  - Retargeted the seven components importing the rail widths, and the
    end-to-end page object, onto the new modules.
  - Containerised authentication for the private library: three Dockerfiles,
    one composite action and six workflows.
  - `useFdsThemeScope` reshaped to write the design-system theme class on the
    document root (the library portals flyouts and tooltips to `document.body`,
    so a subtree-scoped class would leave them unthemed).
- Friction / process feedback: recorded in `LIBRARY-FEEDBACK.md` (five
  library entries) and reported separately as playbook corrections.

#### Pre-existing issues found, dated and deliberately NOT fixed here

This pull request is mono-subject. The following were found while working on
the navigation, are older than this change, and are left untouched.

- **2026-08-04 — Two components read the collapsed-rail flag without
  subscribing to the toggle channel.**
  `opencti-front/src/components/graph/GraphToolbar.tsx` (line 32) and
  `opencti-front/src/private/components/data/ToolBar.jsx` (line 69) read
  `localStorage.getItem('navOpen')` during render but never subscribe to
  `MESSAGING$.toggleNav`, unlike the eight other readers. Their left offset is
  therefore stale until the next re-render for another reason: collapse the
  rail with a graph open and the graph toolbar stays offset for the old width.
  Pre-dates this change — the previous rail emitted the same notification.
  Fix belongs in its own pull request: subscribe like the other eight, or
  extract a shared `useNavOpen()` hook and use it in all ten places.

- **2026-08-04 — `yarn i18n-checker` is declared but cannot run.**
  `opencti-front/package.json` declares the `i18n-checker` script, but
  `i18n-checker.js` does not exist anywhere in the repository and no
  continuous-integration job invokes it. Locale drift is therefore unchecked.
  Flagged for the OpenCTI team: either restore the script and wire it into
  the front-end quality workflow, or drop the dead entry. The nine locale
  files were verified symmetric by hand for this change (5384 keys each).
