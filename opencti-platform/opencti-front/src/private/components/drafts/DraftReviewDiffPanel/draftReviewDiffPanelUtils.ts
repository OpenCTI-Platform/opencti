import { Change } from '../../../../components/common/table/ChangesTable';

export interface PatchValue {
  initial_value: string[];
  replaced_value: string[];
  added_value: string[];
  removed_value: string[];
}

export type UpdatesPatch = Record<string, PatchValue>;

export type RenderChangeValuesFn = (
  values?: readonly string[] | null,
  isRemoved?: boolean,
  idLabelMap?: Record<string, string>,
) => React.ReactNode;

export const EXCLUDED_PATCH_FIELDS = new Set(['standard_id', 'objects']);

export const STIX_ID_REGEX = /^[a-z][a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const isResolvableId = (value: string): boolean => STIX_ID_REGEX.test(value) || UUID_REGEX.test(value);

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
