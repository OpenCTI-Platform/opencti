# Navigation and placement

The left menu is data: `src/private/components/nav/useNavMenu.tsx` returns groups of entries, and
`filterNavGroups` drops what the user may not see. Where a new surface goes is decided by the
information architecture rules of OpenCTI-Platform/opencti#18685 (R1-R10). The short version:

- **No new top-level entry.** A new list page is a sub-item of an existing section (Analyses, Cases,
  Events, Observations, Defense, Data...). Only the Defense hub was added for the autonomous threat
  management program.
- **Secondary surfaces are tabs** on the entity they belong to (`StixDomainObjectTabsBox`). Time
  views go in the Changes tab, graph analytics in the Similar tab; do not add a tab per feature.
- **Settings go under existing settings pages** (mostly Settings > Customization). Dashboards ship
  as built-in templates and widgets in the catalog, never as menu entries.
- **Actions go in existing menus.** AI actions go in the Ask AI menu (`StixCoreObjectAskAI`); other
  actions go in the entity's more-actions popover. Do not add a row of header buttons.

## Registering a Defense area

The Defense hub (`/dashboard/defense`) and its menu entry exist only while an area is registered.
An area is one file in `src/private/components/defense/areas/`, whose default export is its
`DefenseArea`; `defenseAreas.tsx` collects the files and orders them. One file gives both the menu
row and the route, and adding an area touches no other file:

```tsx
// src/private/components/defense/areas/hunts.tsx
import React, { lazy } from 'react';
import { Crosshairs } from 'mdi-material-ui';
import { KNOWLEDGE } from '../../../../utils/hooks/useGranted';
import type { DefenseArea } from '../defenseAreas';

const hunts: DefenseArea = {
  order: 10,
  path: 'hunts',
  label: 'Hunts',
  icon: <Crosshairs fontSize="small" />,
  entityType: 'Hunt',
  needs: [KNOWLEDGE],
  component: lazy(() => import('../../hunts/RootHunts')),
};

export default hunts;
```

- `order` places the area in the menu: Hunts 10, Defense matrix 20, Dissemination assurance 30.
- `path` is the route segment (`/dashboard/defense/hunts/*`); the component mounts its own
  sub-routes. Do not add a route for it in `Index.tsx`: the hub's `/defense/*` route mounts it.
- `label` is an English source string, translated by the menu, so it must exist in every
  `lang/front/*.json` file.
- `entityType` hides the area with that entity type (Customization > Entity types).
- `needs` lists the capabilities that grant the area (any of them); without it the area is shown to
  every user who sees the knowledge menu. The component still guards its own actions with `Security`.

## Registering a Curation tab

The Data > Curation hub (`/dashboard/data/curation`) works the same way with one file per tab in
`src/private/components/data/curation/tabs/`, whose default export is its `CurationTab`
(`{ order, path, label, needs?, component }`; Inbox 10, Conflicts 20, Stale knowledge 30, Merges 40,
Knowledge health 50). The hub renders the breadcrumbs and the tab bar; the component renders the
tab's content only.

`defenseAreas.test.ts` checks both registries: unique, lowercase route segments, unique ascending
positions and sentence-case labels.
