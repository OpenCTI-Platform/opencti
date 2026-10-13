import { isFeatureEnabled } from '../../config/conf';
import { generateBuiltInExportId } from '../../schema/identifier';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_ROLE, ENTITY_TYPE_SETTINGS, ENTITY_TYPE_THEME } from '../../schema/internalObject';
import { ENTITY_TYPE_VOCABULARY } from '../vocabulary/vocabulary-types';
import { ENTITY_TYPE_EMAIL_TEMPLATE } from '../emailTemplate/emailTemplate-types';
import { ENTITY_TYPE_NOTIFIER } from '../notifier/notifier-types';
import { ENTITY_TYPE_FINTEL_TEMPLATE } from '../fintelTemplate/fintelTemplate-types';
import { BUILT_IN_VOCABULARIES } from './globalExport-built-in-vocabularies';
import type { BasicStoreIdentifier } from '../../types/store';

export type NaturalKey = Record<string, string>;

// Creation input that may carry an export_id. It is not part of the GraphQL inputs: only the platform sets it.
export type WithExportId<T> = T & Pick<BasicStoreIdentifier, 'export_id'>;

// A type whose built-in elements get an export_id: the same on every platform, so that an import finds the element
// instead of creating a duplicate, even after it was renamed. Only the built-in elements that can be renamed or recreated,
// and whose standard_id cannot identify them across platforms, get one (plus Settings and themes, referenced by the export).
type BuiltInExportIdSpec = {
  entityType: string;
  // Natural key of an element, from its creation input or from the stored element. Undefined when the element is not built-in.
  naturalKey: (element: Record<string, any>) => NaturalKey | undefined;
  // Natural keys of the built-in elements of a platform, frozen: the backfill of existing platforms looks for them
  builtIns: NaturalKey[];
};

const byName = (element: Record<string, any>) => ({ name: element.name });
const byNames = (names: string[]) => names.map((name) => ({ name }));

export const BUILT_IN_EXPORT_ID_SPECS: BuiltInExportIdSpec[] = [
  { entityType: ENTITY_TYPE_SETTINGS, naturalKey: () => ({}), builtIns: [{}] },
  {
    entityType: ENTITY_TYPE_THEME,
    naturalKey: (element) => (element.built_in === true ? { name: element.name } : undefined),
    builtIns: byNames(['Filigran Dark', 'Filigran Light']),
  },
  { entityType: ENTITY_TYPE_GROUP, naturalKey: byName, builtIns: byNames(['Default', 'Administrators', 'Connectors']) },
  { entityType: ENTITY_TYPE_ROLE, naturalKey: byName, builtIns: byNames(['Default', 'Administrator', 'Connector']) },
  {
    entityType: ENTITY_TYPE_VOCABULARY,
    // Some vocabularies are declared with surrounding spaces, they are stored trimmed
    naturalKey: (element) => ({ category: element.category, name: element.name.trim() }),
    builtIns: Object.entries(BUILT_IN_VOCABULARIES).flatMap(([category, names]) => names.map((name) => ({ category, name }))),
  },
  { entityType: ENTITY_TYPE_EMAIL_TEMPLATE, naturalKey: byName, builtIns: byNames(['Built-In Template For Onboarding']) },
  {
    entityType: ENTITY_TYPE_NOTIFIER,
    naturalKey: byName,
    builtIns: byNames(['Sample of Microsoft Teams message for live trigger', 'Sample of Microsoft Teams message for digest trigger']),
  },
  {
    entityType: ENTITY_TYPE_FINTEL_TEMPLATE,
    naturalKey: (element) => ({ name: element.name, target_type: [element.settings_types].flat()[0] }),
    builtIns: [
      ...['Report', 'Grouping', 'Case-Incident', 'Case-Rfi', 'Case-Rft'].map((target_type) => ({ name: 'Executive Summary', target_type })),
      { name: 'Incident Response Report', target_type: 'Case-Incident' },
    ],
  },
];

export const BUILT_IN_EXPORT_ID_TYPES = BUILT_IN_EXPORT_ID_SPECS.map((spec) => spec.entityType);
const SPECS_BY_TYPE = new Map(BUILT_IN_EXPORT_ID_SPECS.map((spec) => [spec.entityType, spec]));

// export_id of a built-in element, undefined when its type has no export_id or the element is not built-in
export const builtInExportIdOf = (entityType: string, element: Record<string, any>): string | undefined => {
  const naturalKey = SPECS_BY_TYPE.get(entityType)?.naturalKey(element);
  return naturalKey ? generateBuiltInExportId(entityType, naturalKey) : undefined;
};

// Returns the creation input of a built-in element with its export_id. The export_id attribute only exists when
// GLOBAL_EXPORT_BUNDLE is enabled: otherwise the input is returned unchanged, as the strict mapping would reject the field.
export const withBuiltInExportId = <T extends Record<string, any>>(input: T, entityType: string): WithExportId<T> => {
  const exportId = isFeatureEnabled('GLOBAL_EXPORT_BUNDLE') ? builtInExportIdOf(entityType, input) : undefined;
  return exportId ? { ...input, export_id: exportId } : input;
};
