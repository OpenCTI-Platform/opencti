# Changes Tab Sections

The **Changes** tab of an entity is its single time tab: comparing two dates, viewing the entity as it was at a past date, and any other view of how the entity evolved (merges, provenance changes). Sections are registered in `ENTITY_CHANGES_SECTIONS` (`src/private/components/common/changes/entityChangesSections.tsx`) and rendered by the single tab component `common/changes/EntityChangesTab.tsx`; never add a separate tab such as "Diff" or "Merge history", nor a second Changes tab or route.

## Registering a section

- Add an entry `{ key, label, Component }` to `ENTITY_CHANGES_SECTIONS`, in display order. `label` is an i18n key in sentence case ("Compare dates", "View as of"), translated in every language file.
- `Component` receives `{ entityId, basePath }`. The selected section is kept in the `section` search parameter; the section's own state (period, date) also goes in the URL, so every view can be shared and survives a reload.
- A link that names no section opens the first section whose optional `matchesLink(searchParams)` accepts its other parameters (a link carrying a date opens "View as of"), else the first section.
- Links into a section use the helpers of `timeMachineUtils.ts` (`changesSearch`, `comparePeriodSearch`, `sinceLastVisitSearch`), never hand-built query strings.

## Section anatomy

Every section follows the same structure, top to bottom:

1. **Toolbar row**: the controls that scope the section (period selector, date picker) on the left, its actions (for instance "Export") on the right. No separate row for a single action.
2. **One-line summary with counts**: only the measures that changed get a card; unchanged measures are folded into one caption ("Unchanged during this period: ..."). A card never shows "-": a value that was never set reads "Not set".
3. **The table or list** of the changes. Each row names its operation with a translated label ("Added", "Changed", "Removed", "Revoked") and a chip tone by meaning (success for additions, error for removals, warning for revocations, info for changes). Before and after values carry the same tones with an icon, so colour is never the only signal; removed values are struck through. Dates use the relative form with the absolute date in a tooltip (`TimeMachineDate`).
4. **An empty state that offers its action**: an empty period offers a wider one ("Compare the last 90 days"), an empty as-of view offers "Go to the first recorded change", a scope with nothing to compare offers "Choose a scope". Never a bare "No data".

No section-level breadcrumb: the entity header and the tab already locate the user.

## Wording

- One translated message per sentence, with ICU arguments and plurals: `t_i18n('{count, plural, one {# change} other {# changes}}', { values: { count } })`. Never assemble a sentence from translated fragments (`${t_i18n('Change on')} ${date}`) or a plural from a count and a separate word.
- No raw enum values, identifiers or keys on screen: relationship actions such as `confidence_changed` render through labels.
