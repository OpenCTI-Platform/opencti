---
name: create-e2e-test
description: "Use when: writing or extending Playwright E2E tests for opencti-front, especially when leveraging a browser (VS Code integrated browser, Playwright MCP, or codegen) to inspect the live app DOM before authoring locators/steps"
---

# Create E2E Test (Playwright + live-browser-driven authoring)

E2E tests live in `opencti-platform/opencti-front/tests_e2e/` and run against a real running
platform (frontend + backend + Elastic/Redis/RabbitMQ/MinIO). This skill covers both the
mechanics of the test suite (page models, fixtures, tags, config) AND the recommended
browser-driven authoring workflow: navigate the live app, inspect the real DOM/accessibility tree,
and let that context drive locator choices instead of guessing selectors. Step 0 has two variants
depending on which client/tooling is available — use whichever matches your environment.

## Prerequisites
- A running dev stack: `opencti-platform/opencti-dev` (`docker compose up -d`) + backend/frontend
  dev servers (`yarn dev` from repo root, or `yarn start` from `opencti-platform/opencti-front`).
  Frontend dev server is `http://localhost:3000`.
- Credentials: default admin is `admin@opencti.io` / `admin` (see
  `opencti-platform/opencti-graphql/config/development.json` under `app.admin`). This is already
  the default used by `tests_e2e/model/form/loginForm.pageModel.ts`'s `login()` method, so specs
  never hardcode it themselves.

## Step 0 (VS Code) — Explore the live app with the integrated browser tool
This is the technique that makes authoring faster and locators more reliable in VS Code, where a
built-in browser tool (open/navigate/click/type/read-snapshot/screenshot) is available in chat:
1. Open the target page with the browser tool (open a new page or navigate an existing shared one).
2. Log in if needed (Login/Password fields, "Sign in" button - use the dev credentials above).
3. Use the page-snapshot/read tool (accessibility tree) rather than a screenshot to decide on
   locators — it exposes roles, labels, and any existing `data-testid`s directly, which map
   straight onto Playwright's `getByRole`/`getByLabel`/`getByTestId`. Use a screenshot only for
   visual confirmation (e.g. checking a graph/canvas like the workflow React Flow editor, which
   doesn't expose much in the accessibility tree).
4. Click through the exact flow you want to test (open a drawer, fill a field, submit) to confirm
   real element names/labels/testids before writing the spec — don't guess them.
5. Prefer navigating directly via URL (`navigate_page`) once you know the route, instead of
   re-clicking through menus every time you re-check something.

## Step 0 (IntelliJ / Copilot CLI / no integrated browser tool) — Alternative
Without a chat-integrated browser, get the same live-DOM grounding through tools already in this
repo, instead of guessing locators from source reading alone:
1. **Playwright codegen** (`yarn generate-test-e2e`, i.e. `yarn playwright codegen
   http://localhost:3000/`) opens a real, separate browser window plus a recorder window. Log in
   manually once, then click through the flow you want to test — it generates Playwright locators
   (preferring role/label, same priority as this repo's convention) and prints them live as you
   interact. Copy the generated locators/steps into a proper page model + spec rather than keeping
   the raw recorder output (it doesn't know about `baseFixtures`, page models, or tags).
2. **Manual DevTools inspection**: open `http://localhost:3000` in your own browser, log in with
   the dev credentials, and use the browser's accessibility tree / Elements panel (or the
   Playwright VS Code extension's "Pick locator" if installed) to confirm exact roles/labels/
   `data-testid`s before writing the spec.
3. **Playwright MCP server**: if the environment has an MCP client configured with the
   [Playwright MCP server](https://github.com/microsoft/playwright-mcp), its
   `browser_navigate`/`browser_snapshot`/`browser_click`/`browser_type` tools give the same
   accessibility-snapshot-driven workflow as Step 0 (VS Code) — use it the same way (snapshot
   first, screenshot only for visual/canvas confirmation).
4. Whichever method is used, the output artifact is the same: a page model + spec following Steps
   1-6 below — don't hand-write selectors from memory when a live snapshot/recorder is available.

## Step 1 — Decide where the spec goes
- One folder per feature area under `tests_e2e/<feature>/`, e.g. `tests_e2e/report/report.spec.ts`.
- If the feature is new, create a new folder matching the feature name.
- File name: `<thing>.spec.ts` (e.g. `createNote.spec.ts`, `report.spec.ts`).

## Step 2 — Page models (`tests_e2e/model/`)
- One class per page or reusable component/drawer, named `<Thing>.pageModel.ts` (e.g.
  `report.pageModel.ts`, `reportDetails.pageModel.ts`). Existing form drawers live under
  `tests_e2e/model/form/*.pageModel.ts`; reusable field widgets (text/date/autocomplete/file) live
  under `tests_e2e/model/field/*.pageModel.ts` — reuse those instead of re-implementing input
  handling.
- Constructor takes `private page: Page` (and sometimes a scoping `Locator`/label per field).
- Expose **getters** that return Locators (`getPage()`, `getCreateButton()`, ...) and **action
  methods** that perform interactions and return the resulting promise (`openNewReportForm()`,
  `login()`, ...). Keep assertions out of page models — assert in the spec.
- Locator priority (mirrors Playwright best practice and this repo's convention): `getByRole` /
  `getByLabel` / `getByText` first, then `getByTestId` when there's no reliable accessible name
  (e.g. icon-only buttons, chips in a graph, list rows).
- Navigation helpers commonly expose both `goto()` (direct URL, use only when necessary — e.g.
  once at test start) and `navigateFromMenu()` (uses `LeftBarPage`/menu page models — prefer this
  for realistic navigation).

## Step 3 — When to add a `data-testid`
Only add one to a production component (`opencti-platform/opencti-front/src/**`) when the element
truly cannot be targeted reliably via role/label/text — e.g. a bare `<div>` wrapping a whole page/
section (`data-testid="report-page"`), an icon-only button, or nodes in a non-accessible canvas
like the React Flow workflow graph. Convention: kebab-case, describing the element
(`report-details-page`, `create-report-button`, `create-widget-button`). Don't add test-only props
to satisfy a single spec if an existing role/label already gets you there.

## Step 4 — Writing the spec
```ts
import { expect, test } from '../fixtures/baseFixtures'; // NOT '@playwright/test' directly
import ReportPage from '../model/report.pageModel';
import ReportFormPage from '../model/form/reportForm.pageModel';

test('Report CRUD', { tag: ['@report', '@knowledge', '@mutation', '@ce', '@group1'] }, async ({ page }) => {
  const reportPage = new ReportPage(page);
  const reportForm = new ReportFormPage(page);

  await reportPage.goto();
  await reportPage.navigateFromMenu();
  await reportPage.openNewReportForm();
  await expect(reportForm.getCreateTitle()).toBeVisible();
  // ...
});
```
- Always import `test`/`expect` from `../fixtures/baseFixtures` (adds coverage + base-path
  handling), not from `@playwright/test`.
- Tag every `test(...)`/`test.describe(...)` with at least an edition tag (`@ce` or `@ee`) and,
  if the test writes data, `@mutation`. Add a feature tag (`@report`, `@pir`, ...) and a
  `@group<N>` sharding tag matching sibling specs in the same area (check neighboring specs for
  the group already in use, or start a new one only if none fits).
- Keep one scenario per `test()`; use several `test()`s in a `test.describe()` for variants.
- For multi-account flows (logout/login as a different user mid-test), follow the pattern in
  `tests_e2e/dashboard/dashboardRestriction.spec.ts`.
- Random/test data should stay short and deterministic when possible (e.g. `fakeDate()` from
  `tests_e2e/utils.ts`, or a `uuid()`/timestamp suffix only where uniqueness is required).

## Step 5 — Test data & Playwright config
- Seed data (users/groups/roles/orgs/STIX) lives in `tests_e2e/dataForTesting/` — see its
  `README.md`. Reuse an existing `[type].data.ts` helper or add a new one following `user.data.ts`,
  then wire it into `init.data.ts`.
- `playwright.config.ts` defines project dependencies: `setup` (auth) → `init data` (seeds) →
  `chromium` (actual specs), all sharing `storageState: 'tests_e2e/.setup/.auth/user.json'`. Add a
  new project only if a feature needs its own one-time setup fixture that other specs depend on.

## Step 6 — Run & verify
From `opencti-platform/opencti-front`:
```bash
yarn test:e2e                      # full suite, headless
yarn test:e2e:ui                   # Playwright UI mode (interactive/debug)
yarn playwright test tests_e2e/report/report.spec.ts   # single file
yarn generate-test-e2e             # Playwright's own codegen recorder, alt. to Step 0
```
Confirm the new/changed spec passes before considering the task done.
