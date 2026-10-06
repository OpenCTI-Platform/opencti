# Navigation and placement

The left menu is data: `src/private/components/nav/useNavMenu.tsx` returns groups of entries, and
`filterNavGroups` drops what the user may not see. Where a new surface goes follows the information
architecture rules of OpenCTI-Platform/opencti#18685. The short version:

- **No new top-level entry.** A new list page is a sub-item of an existing section (Analyses, Cases,
  Events, Observations, Defense, Data...). Defense is the one knowledge section built as a hub: its
  pages are registered areas, as described below.
- **Secondary surfaces are tabs** on the entity they belong to (`StixDomainObjectTabsBox`); do not
  add a tab per feature.
- **Settings go under existing settings pages** (mostly Settings > Customization). Dashboards ship
  as built-in templates and widgets in the catalog, never as menu entries.
- **Actions go in existing menus.** AI actions go in the Ask AI menu (`StixCoreObjectAskAI`); other
  actions go in the entity's more-actions popover. Do not add a row of header buttons.

## The two hubs

| Hub | Address | Menu | Registry | One file per entry in |
| --- | --- | --- | --- | --- |
| Defense | `/dashboard/defense` | knowledge group, right after Observations | `DEFENSE_AREAS` (`defense/defenseAreas.tsx`) | `src/private/components/defense/areas/` |
| Curation | `/dashboard/data/curation` | Data, right after Relationships | `CURATION_TABS` (`data/curation/curationTabs.tsx`) | `src/private/components/data/curation/tabs/` |

Each registry collects the default exports of the files of its folder (`import.meta.glob`), ordered
by `order`. Adding an entry is adding one file: it gives both the menu row and the route, and edits
no shared navigation or routing file (its strings still go into every `lang/front/*.json` file).

The platform ships both hubs with an empty registry. While nothing is registered, the menu lists the
hub as a plain link and the hub lands on its own first-use page (`common/hub/HubEmpty.tsx`), which
names the hub, says what it is for and that its pages are not available yet, and links to its
documentation. Once an entry is registered, the hub opens its first entry instead, and the menu lists
the hub only while one of its entries is visible to the reader: a reader whose entries are all hidden
(entity type hidden, capability missing, platform module disabled) sees no menu entry, and a direct
link shows the no-access page (`common/hub/HubNoAccess.tsx`) with a way back. Both hubs require
access to the knowledge, from the menu and from a direct link alike.

## Registering a Defense area

An area is one file in `src/private/components/defense/areas/`, whose default export is its
`DefenseArea`:

```tsx
// src/private/components/defense/areas/example.tsx
import React, { lazy } from 'react';
import { ShieldSearch } from 'mdi-material-ui';
import { KNOWLEDGE } from '../../../../utils/hooks/useGranted';
import type { DefenseArea } from '../defenseAreas';

const example: DefenseArea = {
  order: 10,
  path: 'example',
  label: 'Example area',
  description: 'Which question does this area answer?',
  icon: <ShieldSearch fontSize="small" />,
  entityType: 'Example-Type',
  needs: [KNOWLEDGE],
  // An object's own page (`/dashboard/defense/example/<id>/...`) has its header and tabs.
  rendersOwnPage: (subPath) => subPath.length > 0,
  component: lazy(() => import('../../example/RootExample')),
};

export default example;
```

- `order` places the area in the menu; two areas never share a position.
- `path` is the route segment (`/dashboard/defense/example/*`); the component mounts its own
  sub-routes. Do not add a route for it in `Index.tsx`: the hub's `/defense/*` route mounts it.
- `label` is an English source string, translated by the menu, so it must exist in every
  `lang/front/*.json` file.
- `description` is the question the area answers, an English source string in every language file.
  The area's first-use state shows it (see below).
- `entityType` hides the area with that entity type (Customization > Entity types).
- `needs` lists the capabilities that grant the area (any of them); without it the area is shown to
  every user who sees the knowledge menu. The component still guards its own actions with `Security`.
- `sections` lists the area's pages (`{ path, label }`, in order) when it has several: the hub shows
  them as tabs and adds the open one to the breadcrumb (Defense / Example area / Overview).
- `rendersOwnPage(subPath)` is true for a path below the area that the area renders as a page of its
  own, typically an entity page with its header and tabs; the hub adds nothing around it.
- `useBadgeCount` is a hook returning the pending work of the area (results to triage, proposals to
  review), never a total; the menu row shows it as a badge. It may suspend or fail: the menu waits for
  nothing and hides the badge.

### The hub owns the page

The hub renders the page of every area: its container, its breadcrumb (Defense / <area>, then the
open section) and its section tabs. An area or tab file **never renders its own breadcrumb or page
container**; it renders its content only, which keeps every area identical in structure. The area's
code loads inside the page, so the breadcrumb and the tabs stay on screen meanwhile.

Inside the page, build the area on the hub page anatomy of the UX charter (OpenCTI-Platform/opencti#18685):
a KPI strip of 3 to 5 counters, the main list, a right drawer for detail. When the area has nothing yet,
render `HubFirstUse` (`src/private/components/common/hub/HubFirstUse.tsx`) with its one primary action
and its documentation link: it shows the area's name and description from the registry, so every area
explains itself the same way.

```tsx
<HubFirstUse
  action={<Button onClick={openCreation}>{t_i18n('Create the first one')}</Button>}
  documentationUrl="https://docs.opencti.io/latest/usage/defense-hub/"
/>
```

## Registering a Curation tab

The Data > Curation hub works the same way with one file per tab in
`src/private/components/data/curation/tabs/`, whose default export is its `CurationTab`
(`{ order, path, label, description?, needs?, isAvailable?, useBadgeCount?, component }`).
`isAvailable(modules)` keeps the tab, and its badge query, out of the hub while the platform module it
belongs to is disabled. The hub renders the breadcrumb (Data / Curation / <tab>) and the tab bar, and
keeps them on screen while a tab's code loads; the component renders the tab's content only and uses
`HubFirstUse` for its first-use state. A tab's `useBadgeCount` shows on its tab, and the counts of all
tabs are summed on the Data > Curation menu row.

## Tests

`defenseAreas.test.ts` checks both registries, whatever they contain: unique, lowercase route
segments, unique ascending positions and sentence-case labels and descriptions. A new entry passes
them before it can merge. The hub chrome is covered by `defense/Root.test.tsx`,
`data/curation/Root.test.tsx` and `nav/useNavMenu.registries.test.tsx`, which render the hubs with
sample entries, and by the end-to-end spec `tests_e2e/hubs/hubs.spec.ts`, which opens both hubs on a
running platform.
