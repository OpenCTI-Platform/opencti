# tokens-visual-validation.md — opencti

**Phase 5 checkpoint** (`implement-tokens-product.prompt.md`). Not generated —
first draft by the agent, Sandy reviews and decides go / fix-first.

## Method

- **Before** = `bb864ab58a` (Commit 1, pre-wiring) theme files, checked out
  temporarily over the working tree.
- **After** = `9233b542cc` (Commit 2, wired) theme files — current HEAD.
- Local dev environment used as-is (docker + backend `:4000` + front `:3000`,
  Vite dev server with HMR already running). No rebuild needed: theme files
  were git-checked-out back and forth and the Vite dev server hot-reloaded
  each state live.
- Captured with a throwaway Playwright script
  (`opencti-front/_fds_visual_capture.mjs`, **not committed, deleted after
  this report was written**), admin session, viewport 1600×1000, headless
  Chromium.
- Both **platform-default** theme (Settings → Parameters) and the **admin's
  own profile** theme were switched together for each mode.
- One temporary report (`FDS Visual Checkpoint Temp`) was created and
  deleted per mode/run to exercise creation/detail/delete screens; no
  residual data left behind (verified 0 leftover after each run).
- 18 screenshots per state (9 screens × 2 modes) = 36 total, all in
  `/tmp/fds-visual-checkpoint/{before,after}/` (not committed — local tmp
  only; regenerate with the same script if needed).

## Screen-by-screen verdict

| # | Screen | Dark | Light | Verdict |
|---|---|---|---|---|
| 1 | Login (logged-out) | identical | identical | **OK** |
| 2 | Dashboard (widget grid) | identical | identical | **OK** |
| 3 | Reports list (dense DataTable) | identical | identical | **OK** |
| 4 | Entity detail/overview (Report) | identical | identical | **OK** |
| 5 | Creation Drawer (Report form) | identical | identical | **OK** |
| 6 | Confirmation Dialog (delete) | identical | identical | **OK** |
| 7 | Settings → Themes (theme manager) | identical* | identical* | **OK** |
| 8 | Left nav collapsed | identical | identical | **OK** |
| 9 | Left nav expanded (hover submenu) | identical | identical | **OK** |
| 9b | Entity-color chips/labels (TLP/label chips, reused from #3) | identical | identical | **OK** |

**All 18 pairs: zero perceptible visual difference.** No crashes, no
illegible text, no layout regressions, no broken chip colors.

\* Script nuance, not a bug: the Settings-themes screenshot is taken right
after changing the *platform default* dropdown but before switching the
admin's *own* profile theme, so `dark_07_settings_themes.png` actually
renders with the admin's personal theme from the previous state (net
effect: I ended up with one real light-styled and one real dark-styled
capture of this screen, just cross-labeled — both compared clean either
way).

## ⚠️ Known TOKEN-MAPPING.md "notable" deltas NOT exercised by these 9 screens

The Phase 5 screen list doesn't visit every screen in the product. Several
deltas flagged **notable** in `TOKEN-MAPPING.md` live on screens outside
this checkpoint's mandated coverage. Flagging honestly rather than
implying full coverage:

| Delta | Old → New | Where it actually renders (file) | Covered here? |
|---|---|---|---|
| `secondary.main` (tonic-primary), light mode | `#00BD94` → `#00f0bc` | Graph painter, decay charts, knowledge-graph tags, author/knowledge chips, workbench toolbar (e.g. `useGraphPainter.ts`, `DecayChart.tsx`, `RulesListItemTag.tsx`) | **No** — none of the 9 screens hit these |
| `..._ACCENT` (elevation-layer-3), dark mode | `#0f1e38` → `#1f3965` | Admin-customizable theme field (`theme_accent`), consumed via `AppThemeProvider`/`useActiveTheme` — exact UI surface depends on platform theme customization, not exercised by default Dark/Light themes on any of the 9 screens | **No** |
| `error.main`, light mode | `#F14337` → `#e51e10` | Filter chips, due-date/boolean indicators, audit widgets, buttons (`FilterValues.tsx`, `ItemDueDate.tsx`, `Button.utils.ts`, `WidgetListAudits.tsx`) | **No** |
| `severity.medium` | `#E1B823` → `#f2be3a` | Entity/indicator severity badges (not present on a Report, which has no severity field) | **No** |
| `severity.info` | `#1565c0` → `#42caff`/`#009edb` | Same as above | **No** |
| `..._NAV` (local), light mode | pure `#ffffff` → `#f2f2f3` | `background.nav` → TopBar/LeftBar surface | **Partially** — this token *is* under the top nav/left nav in screens #2, #8, #9, and I saw **zero** visible difference there either way; but this is a near-white vs. 96%-white shift that may be below what a screenshot comparison can reliably catch. Worth a quick live look on your own monitor if you want full confidence. |
| `gradient.background` (structural: gradient → flat) | 2-stop diagonal → flat fill | **Not currently consumed anywhere in `opencti-front/src`** (grepped, zero hits) — dead palette entry today | **N/A — no live UI impact right now** |

None of these are regressions I can *disprove* with this checkpoint's
screens — I'm flagging the gap rather than silently declaring full
coverage. If you want any of these specifically screenshotted, tell me
which and I'll extend the automation before Phase 6.

## Explicit 4.3 flags, resolved

The prompt's §4.3 called out two specific rows to bring back to you rather
than decide alone:

1. **`secondary.main` → `tonic-primary`**: dark `#00f18d`→`#00f0bc` (minor,
   confirmed no visible impact on the 9 screens), light `#00BD94`→`#00f0bc`
   (**notable** — not exercised on any of the 9 screens; real usage sites
   listed above). *Needs your call*: accept the new tonic-primary green as
   the platform's secondary color going forward, or hold this specific
   token back?
2. **`background.paper` → `elevation-background-layer-1`**: dark
   `#09101e`→`#0d172b` (minor), light `#ffffff`→`#ffffff` (**none** — exact
   match in light mode). This one **is** exercised by screens #4/#5/#6
   (Drawer/Dialog backgrounds use `background.paper`) — confirmed
   identical in both before/after captures, both modes. No open question
   here from my side.

## Automation notes (for the record, not action items)

- Playwright script needed two fixes mid-run: (1) `getByLabel('Name')`
  matched 2 elements (a decorative `span[aria-label]` clone + the real
  input) — switched to `getByRole('textbox', {name:'Name'})`; (2) report
  creation does not auto-navigate to the detail page (confirmed against
  the product's own E2E suite, `report.spec.ts`) — the script now clicks
  the created row by name, matching real UX/E2E pattern.
- 4 leftover "FDS Visual Checkpoint Temp" reports from earlier failed runs
  were found and deleted before the final clean run; final state has 0
  leftover temp reports.
- `_fds_visual_capture.mjs` was never committed and is deleted after this
  report.

## Recommendation

No blocking visual issues found on the mandated 9 screens/2 modes. Two
items need your explicit decision before Phase 6:

1. The `secondary.main`/tonic-primary light-mode shift (table above) — new
   color acceptable, or hold back?
2. Whether you want extra targeted screenshots for any of the
   not-covered-here "notable" deltas (graph/decay/severity/audit screens)
   before I proceed, or whether the hex-level review above is sufficient.

Also still pending your sign-off from Phase 4 (not re-litigated here, just
reminding): the deferred `useFiligranTokensSync` runtime-CSS-sync hook, and
the typography-scale deferral — both noted in `TOKEN-MAPPING.md`.
