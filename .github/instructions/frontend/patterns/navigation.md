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

The Defense hub (`/dashboard/defense`) and its menu entry exist only while an area is registered in
`src/private/components/defense/defenseAreas.tsx`. One entry gives both the menu row and the route:

```tsx
const RootHunts = lazy(() => import('../hunts/Root'));

export const DEFENSE_AREAS: DefenseArea[] = [
  { path: 'hunts', label: 'Hunts', icon: <Crosshairs fontSize="small" />, entityType: 'Hunt', component: RootHunts },
];
```

- `path` is the route segment (`/dashboard/defense/hunts/*`); the component mounts its own sub-routes.
- `label` is an English source string, translated by the menu, so it must exist in every
  `lang/front/*.json` file.
- `entityType` hides the area with that entity type (Customization > Entity types).
- The component checks its own capabilities with `Security`; the menu row only requires `KNOWLEDGE`.

## Registering a Curation tab

The Data > Curation hub (`/dashboard/data/curation`) works the same way with
`src/private/components/data/curation/curationTabs.tsx`. Each tab is `{ path, label, component }`.
The hub renders the breadcrumbs and the tab bar; the component renders the tab's content only.

`defenseAreas.test.ts` checks both registries: unique, lowercase route segments and sentence-case
labels.
