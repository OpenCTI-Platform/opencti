import { Change } from '../../../../components/common/table/ChangesTable';

export interface PatchValue {
  initial_value: string[];
  replaced_value: string[];
  added_value: string[];
  removed_value: string[];
}

export type UpdatesPatch = Record<string, PatchValue>;

/** Render function passed down to change display components to format field values (removed or added). */
export type RenderChangeValuesFn = (
  values?: readonly string[] | null,
  isRemoved?: boolean,
  idLabelMap?: Record<string, string>,
) => React.ReactNode;

/** Fields present in every STIX patch but not meaningful to display in the diff panel. */
export const EXCLUDED_PATCH_FIELDS = new Set(['standard_id', 'objects']);

/** Matches a STIX ID such as `malware--<uuid>`. */
export const STIX_ID_REGEX = /^[a-z][a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** Matches a plain UUID (used as internal OpenCTI identifiers). */
export const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Returns true if the value looks like a STIX ID or UUID that can be resolved to a label. */
export const isResolvableId = (value: string): boolean => STIX_ID_REGEX.test(value) || UUID_REGEX.test(value);

/**
 * Parses the raw JSON patch stored in `draft_updates_patch` into a list of `Change` objects
 * suitable for the ChangesTable component.
 *
 * The patch format is a map of field name → `PatchValue`. Two strategies are applied:
 * - If `replaced_value` is non-empty, the whole value was replaced: initial → replaced.
 * - Otherwise, individual items were added/removed from the existing list.
 *
 * Fields listed in `EXCLUDED_PATCH_FIELDS` are filtered out.
 */
export const parseUpdatesPatch = (rawPatch: string | null | undefined): Change[] => {
  if (!rawPatch) return [];
  try {
    const patch: UpdatesPatch = JSON.parse(rawPatch);
    return Object.entries(patch)
      .filter(([field]) => !EXCLUDED_PATCH_FIELDS.has(field))
      .map(([field, values]) => {
        if (values.replaced_value && values.replaced_value.length > 0) {
          return {
            field,
            removed: values.initial_value?.map(String) ?? [],
            added: values.replaced_value.map(String),
          };
        }
        const initialList = values.initial_value?.map(String) ?? [];
        const addedItems = values.added_value?.map(String) ?? [];
        const removedItems = values.removed_value?.map(String) ?? [];
        const newList = [
          ...initialList.filter((v) => !removedItems.includes(v)),
          ...addedItems,
        ];
        return {
          field,
          removed: initialList,
          added: newList,
        };
      });
  } catch {
    return [];
  }
};

/**
 * Builds a map of `{ fieldName → humanReadableLabel }` from the entity type's attribute
 * definitions (fetched via the `subType` GraphQL query). Used as a fallback when i18n
 * does not have a translation for a technical field name.
 */
export const buildFieldLabelMap = (
  attributesDefinitions: ReadonlyArray<{ name: string; label: string | null | undefined }> | null | undefined,
): Record<string, string> => {
  if (!attributesDefinitions) return {};
  return Object.fromEntries(
    attributesDefinitions
      .filter((a) => a.label)
      .map((a) => [a.name, a.label as string]),
  );
};

/**
 * Resolves a raw field key to a human-readable label using a three-step fallback:
 * 1. i18n translation (if the result differs from the key itself).
 * 2. Schema-based `labelMap` built from attribute definitions.
 * 3. Best-effort formatting: strips the `x_opencti_` prefix and replaces underscores with spaces.
 */
export const formatFieldKey = (
  field: string | undefined,
  labelMap: Record<string, string>,
  t_i18n?: (key: string) => string,
): string => {
  if (!field) return '';
  if (t_i18n) {
    const translated = t_i18n(field);
    if (translated !== field) return translated;
  }
  if (labelMap[field]) return labelMap[field];
  const formatted = field.replace(/x_opencti_/g, '').replace(/_/g, ' ');
  return formatted.charAt(0).toUpperCase() + formatted.slice(1);
};
