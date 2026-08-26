# MUI select surfaces — exhaustive census, one verdict per mount

Generated from the tree at the HEAD of `fds/combobox-conversion`.

**Method.** Every `component={SelectField}` mount (the Formik pivot over MUI
Select) and every raw `<Select` mount outside it, classified by reading 25
lines of context for `multiple` and `renderValue`. `NativeSelect`: **zero**
occurrences in the tree. `<TextField select>`: **zero**. Both were checked
rather than assumed.

**Routing rule.** A closed list with no typing goes to the library `Select`; a
multi-value field goes to `Combobox multiple`, because that is where the chip
row and its per-value tone live. Same routing the Combobox RFC §2.4 applied to
the 12 enumerated `<Select multiple renderValue={chips}>` sites.

**198 mounts** over 97 files — **182** single-value,
**16** multi-value. Every line carries a verdict; none is exempt.

**On the EE column.** It says only that the FILE mentions an enterprise-edition
gate somewhere — not that the field is behind one. Establishing that needs a
banner, a source guard on the field itself, or a server refusal; this round
already over-attributed EE once and will not do it again. 7 mounts sit in
such files and are flagged **verify** rather than **gated**.

## Correction — 2026-08-25, after converting 29 of them

Two things the first pass got wrong, both found by converting rather than by
re-reading:

1. **At least one entry is not a live mount.**
   `data/jsonMapper/representations/attributes/JsonMapperRepresentationAttributeForm.tsx`
   has its only `component={SelectField}` inside a commented-out JSX block
   (`{/** … * */}`). It was converted, eslint reported the new import as unused,
   and that is how the comment was noticed. The site is reverted and stays MUI
   because there is nothing there to convert. Every remaining row must be
   confirmed live at the moment it is converted; a line-based scan cannot tell a
   mount from a commented mount.

2. **The totals hold, and here is the cross-check.** A second pass that masked
   comments returned 120, which was wrong in the other direction — masking
   `/* … */` also eats template literals and anything containing `*/`. The
   defensible count enforces a tag boundary (`<Select` followed by whitespace,
   `>` or end of line, which excludes `<SelectionDrag />` and `<SelectAll />`)
   and reconciles against the work done: 114 pivot mounts, of which **29 are
   now converted** and **85 remain**, plus **84** raw `<Select>` over 33 files.
   114 + 84 = 198, the original total.

**Converted so far (29 mounts):** DisseminationListField · Settings platform
theme and language · RetentionCreation, RetentionEdition · AlertDigestCreation,
AlertDigestEdition · IngestionCsv Creation/Edition · IngestionJson
Creation/Edition · IngestionTaxii Creation/Edition · Feed Creation/Edition ·
JsonMapperDefaultMarking.

| file | line(s) | shape | verdict | EE mention in file |
|---|---|---|---|---|
| `components/InputSliderField.tsx` | 88, 140 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `components/dashboard/DashboardRefreshControl.tsx` | 101 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `components/dashboard/DashboardRelativeDateSelect.tsx` | 44 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `components/fields/BulkTextField/BulkTextModal.tsx` | 72 | raw-MUI-Select / multi | **convert → Combobox multiple** (multi-value, so it needs the chip row) | — |
| `components/fields/DisseminationListField.tsx` | 49 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `components/filters/FilterChipPopover.tsx` | 474 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `components/graph/components/EntitiesDetailsRightBar.tsx` | 138 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `components/list_cards/ListCards.jsx` | 116 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `components/list_lines/ListLines.jsx` | 563 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/HomeDashboardSettings.jsx` | 101, 137, 159 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/analyses/external_references/ExternalReferenceFileImportViewer.tsx` | 240, 268 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/analyses/external_references/StixCoreObjectExternalReferencesLines.tsx` | 525, 555 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/analyses/security_coverages/SecurityCoverageAttackPatterns.tsx` | 183 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/analyses/security_coverages/SecurityCoverageCreation.tsx` | 725 | pivot-SelectField / multi | **convert → Combobox multiple** (multi-value, so it needs the chip row) | — |
| `private/components/analyses/security_coverages/SecurityCoverageEditionOverview.tsx` | 335 | pivot-SelectField / multi | **convert → Combobox multiple** (multi-value, so it needs the chip row) | — |
| `private/components/arsenal/vulnerabilities/VulnerabilityEditionCvss3.jsx` | 191 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/arsenal/vulnerabilities/VulnerabilityEditionCvss4.jsx` | 190 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/ai/AISummaryContainers.tsx` | 123, 147 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/bulk/dialog/BulkRelationDialog.tsx` | 498 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/files/FileManager.jsx` | 378, 406, 499, 517 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/files/LaunchImportDialog.tsx` | 278, 309, 325, 381 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/files/import_files/ImportFilesList.tsx` | 247 | raw-MUI-Select / multi | **convert → Combobox multiple** (multi-value, so it needs the chip row) | — |
| `private/components/common/files/import_files/ImportFilesList.tsx` | 292, 322 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/files/import_files/ImportFilesOptions.tsx` | 75 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/files/workbench/WorkbenchFileContent.jsx` | 4221, 4290 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/files/workbench/WorkbenchFileContent.jsx` | 3458 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/form/AuthorizedMembersField.tsx` | 462 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/form/AuthorizedMembersFieldListItem.tsx` | 110 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/form/CreateFileForm.tsx` | 62 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/form/DynamicResolutionField.jsx` | 191 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/form/MaxShareableMarkingsSelectField.tsx` | 75 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/form/QueryAttributeField.tsx` | 58, 70, 83, 95 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/form/StixCoreObjectFileExportForm.tsx` | 441 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | verify |
| `private/components/common/form/TextFieldAskAI.tsx` | 364 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | verify |
| `private/components/common/identities/IdentityCreation.jsx` | 184 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/location/LocationCreation.tsx` | 152 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/stix_core_objects/StixCoreObjectAskAI.tsx` | 231, 246, 282 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/stix_core_objects/StixCoreObjectFilesAndHistory.jsx` | 352, 380, 447, 527, 545 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/stix_core_objects/StixCoreObjectsExportCreation.jsx` | 152, 188 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/stix_core_objects/StixCoreObjectsSuggestions.jsx` | 382 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/stix_core_relationships/StixCoreRelationshipCreationForm.jsx` | 266 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/stix_core_relationships/StixCoreRelationshipsExportCreation.jsx` | 188, 224 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/stix_domain_objects/StixDomainObjectAttackPatternsKillChain.tsx` | 328 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/stix_domain_objects/StixDomainObjectCreation.jsx` | 796 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/stix_domain_objects/StixDomainObjectHeader.jsx` | 488 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/stix_domain_objects/StixDomainObjectThreatKnowledge.tsx` | 454 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/stix_domain_objects/StixDomainObjectsExportCreation.jsx` | 185, 203, 238 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/stix_nested_ref_relationships/StixNestedRefRelationshipCreation.jsx` | 528 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/common/stix_nested_ref_relationships/StixNestedRefRelationshipCreationFromEntity.jsx` | 764 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/data/DataTableToolBar.jsx` | 1072, 2906 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | verify |
| `private/components/data/IngestionSchedulingField.tsx` | 16 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/data/csvMapper/representations/attributes/CsvMapperDefaultMarking.tsx` | 19 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/data/feeds/FeedCreation.tsx` | 564, 576 | pivot-SelectField / multi | **convert → Combobox multiple** (multi-value, so it needs the chip row) | — |
| `private/components/data/feeds/FeedCreation.tsx` | 652, 699, 714, 751, 761, 764, 789, 799 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/data/feeds/FeedEdition.jsx` | 515, 526 | pivot-SelectField / multi | **convert → Combobox multiple** (multi-value, so it needs the chip row) | — |
| `private/components/data/feeds/FeedEdition.jsx` | 599, 646, 661, 699, 709, 712, 738, 748 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/data/forms/FormSchemaEditor.tsx` | 1074, 1274, 1609, 2023 | raw-MUI-Select / multi | **convert → Combobox multiple** (multi-value, so it needs the chip row) | — |
| `private/components/data/forms/FormSchemaEditor.tsx` | 617, 636, 815, 901, 1047, 1149, 1289, 1300, 1313, 1476, 1497, 1523, 1889, 2038, 2049, 2062 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/data/forms/view/FormFieldRenderer.tsx` | 287 | pivot-SelectField / multi | **convert → Combobox multiple** (multi-value, so it needs the chip row) | — |
| `private/components/data/forms/view/FormFieldRenderer.tsx` | 264 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/data/ingestionCsv/IngestionCsvCreation.tsx` | 417 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/data/ingestionCsv/IngestionCsvEdition.tsx` | 600 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/data/ingestionJson/IngestionJsonCreation.tsx` | 388, 443, 511 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/data/ingestionJson/IngestionJsonEdition.tsx` | 344, 403, 463 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/data/ingestionTaxii/IngestionTaxiiCreation.tsx` | 213, 234 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/data/ingestionTaxii/IngestionTaxiiEdition.tsx` | 321, 344 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/data/jsonMapper/representations/attributes/JsonMapperDefaultMarking.tsx` | 19 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/data/jsonMapper/representations/attributes/JsonMapperRepresentationAttributeForm.tsx` | 84 | pivot-SelectField / multi | **convert → Combobox multiple** (multi-value, so it needs the chip row) | — |
| `private/components/data/playbooks/playbookFlow/PlaybookFlowForm.tsx` | 226 | pivot-SelectField / multi | **convert → Combobox multiple** (multi-value, so it needs the chip row) | — |
| `private/components/data/playbooks/playbookFlow/playbookFlowFields/PlaybookFlowFieldPeriod.tsx` | 28 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/data/playbooks/playbookFlow/playbookFlowFields/PlaybookFlowFieldTriggerTime.tsx` | 38, 57 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/data/sync/SyncCreation.tsx` | 327 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/observations/TypesField.tsx` | 53, 82 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/observations/stix_cyber_observables/StixCyberObservablesExportCreation.jsx` | 210, 228, 261 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/pir/pir_form/PirCreationFormGeneralSettings.tsx` | 73 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/profile/ProfileOverview.jsx` | 374, 392, 410 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/profile/api_tokens/TokenCreationForm.tsx` | 138 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/profile/triggers/TriggerDigestCreation.tsx` | 166, 180, 198 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/profile/triggers/TriggerEditionOverview.tsx` | 402, 418, 437 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/settings/Policies.tsx` | 254 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | verify |
| `private/components/settings/Settings.tsx` | 516, 545 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | verify |
| `private/components/settings/activity/alerting/AlertDigestCreation.tsx` | 162, 176, 194 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/settings/activity/alerting/AlertDigestEdition.tsx` | 188, 203, 222 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/settings/custom_fields/CustomFieldCreation.tsx` | 133 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/settings/hidden_types/HiddenTypesField.tsx` | 198 | pivot-SelectField / multi | **convert → Combobox multiple** (multi-value, so it needs the chip row) | — |
| `private/components/settings/notifiers/NotifierTestDialog.tsx` | 91 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/settings/retention/RetentionCreation.tsx` | 157, 197 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/settings/retention/RetentionEdition.jsx` | 134 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/settings/smtp_configuration/SmtpConfigurationForm.tsx` | 249 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/settings/sso_definitions/LdapProviderForm.tsx` | 545 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/settings/sso_definitions/OidcProviderForm.tsx` | 642 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/settings/sso_definitions/SamlProviderForm.tsx` | 644, 797 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/settings/sso_definitions/SecretFieldControl.tsx` | 90, 132 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/settings/sub_types/scale_configuration/ScaleConfiguration.tsx` | 211 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/settings/themes/ThemeForm.tsx` | 253 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/settings/users/SettingsOrganizationUserCreation.jsx` | 248 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/settings/users/UserCreation.jsx` | 269 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/settings/users/UserTokenCreationForm.tsx` | 139 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/settings/users/edition/UserEditionOverview.tsx` | 257, 288 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/widgets/WidgetAttributesInput.tsx` | 319 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/widgets/WidgetCreationParameters.tsx` | 323, 409, 526, 564, 598, 719, 753, 802, 850 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |
| `private/components/workspaces/dashboards/public_dashboards/PublicDashboardCreationForm.tsx` | 139 | pivot-SelectField / single | **convert → Select lib** (closed list, no typing) | — |
| `utils/ai/ResponseDialog.tsx` | 369 | raw-MUI-Select / single | **convert → Select lib** (closed list, no typing) | — |

## Raw `<Select>` — the triplet rewrite, and what it costs

The pivot needed a child rename. These need a structural rewrite, and the shapes
are now known from doing three of them (`66b9b28`):

| shape | what changes |
|---|---|
| `FormControl` + `InputLabel` + `Select` | collapses into the library compound; `SelectLabel` takes over the association, so the hand-rolled `labelId`/`label` pair disappears rather than being translated |
| bare `Typography` above a `Select` | becomes a real `SelectLabel` — the visible text goes from adjacent to associated, a small accessibility gain |
| `onChange(event)` | becomes `onValueChange(value)`, which changes the HANDLER's signature too: `EntitiesDetailsRightBar.handleSelectEntity` took a `SelectChangeEvent` and read `event.target.value` |

`fullWidth`, `variant`, `size` and `labelId` are all dropped: the library field
owns its own width and geometry.

**The import trap.** Three import shapes exist, and the third defeats a
per-symbol regex: `BulkTextModal` pulled `FormControl`, `InputLabel`, `MenuItem`
and `Select` from ONE combined `@mui/material` import. eslint reported four
undefined components. Handle it explicitly before scaling.

### `FormSchemaEditor` — characterised, not yet converted

The largest single unit left: **20 mounts in one file**. Measured rather than
assumed, so the next session starts from facts:

- **18** are the uniform `FormControl` + `InputLabel` + `Select` triple; **2**
  carry the `InputLabel` with the `FormControl` further up the tree.
- **none** is `multiple` — the file's 29 occurrences of "multiple" belong to its
  own subject matter, not to a select's props. So all 20 route to the library
  `Select`, none to `Combobox`.
- **no** real `<Menu>`, `<MenuList>` or `MuiMenu`, so the `MenuItem` rename is
  safe here.
- `Select` arrives through the **combined** `@mui/material` import — the trap
  above.

Deliberately left for its own pass: 20 structural rewrites, each carrying a
handler-signature change, is precisely the shape that has needed one to three
corrective CI cycles every time this round moved in bulk.

## Third count correction — 2026-08-26

The raw-`<Select>` total needs tightening again, and the method matters more than
the number.

- The census figure, **84**, came from `<Select` followed by whitespace, `>` or
  end of line, minus `SelectFieldFds`. It never checked where `Select` came
  from.
- Scoped to files that actually import MUI's Select — either
  `from '@mui/material/Select'` or a `Select` specifier in a combined
  `@mui/material` import — the live figure is **61 mounts remaining**, plus the
  3 converted in `66b9b28`.

The gap is not yet reconciled: a `<Select` line in a file that does not import
MUI's Select is either a library Select (in a converted file), something inside a
comment, or a match this grep should not be making. One pass with the import
scope applied per line, rather than per file, would settle it.

Recorded rather than quietly replaced. Each of the three counts was tighter than
the last, and the pattern is always the same: a line-based grep cannot tell where
a symbol comes from, and the number it produces is an upper bound until the
import is checked.
