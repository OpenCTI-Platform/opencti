import type { AuthContext, AuthUser } from '../../types/user';
import type { EditInput } from '../../generated/graphql';
import { addAllowedMarkingDefinition, findById, markingDefinitionEditField } from '../../domain/markingDefinition';
import { findAllGroups } from '../../domain/group';
import { generateStandardId } from '../../schema/identifier';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import { booleanTrueFilter } from '../../utils/filtering/filtering-utils';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../configImport/configImport-types';
import { CONFIG_IMPORT_UNCHANGED_REASON, configImportValidationReason, joinConfigImportReasons } from '../configImport/configImport-utils';
import { CONFIG_IMPORT_SENSITIVE_REASON, isConfigImportSensitiveChangeAllowed } from '../user/sensitive-config-import';
import type { BasicStoreEntityMarking } from './marking-export';
import { type MarkingImportConfiguration, markingImportSchema } from './marking-import-schema';

export type MarkingImportCode = 'invalid' | 'built_in' | 'exists' | 'sensitive_config' | 'unchanged';

export type MarkingImportResult = ConfigImportResult<MarkingImportConfiguration, MarkingImportCode> & {
  marking?: BasicStoreEntityMarking;
};

export const markingStandardId = (definitionType: string, definition: string): string => {
  return generateStandardId(ENTITY_TYPE_MARKING_DEFINITION, { definition_type: definitionType, definition });
};

// The markings every platform creates at its initialization: the same on every platform, never written by an import
const BUILT_IN_MARKINGS = [
  ['TLP', 'TLP:CLEAR'],
  ['TLP', 'TLP:GREEN'],
  ['TLP', 'TLP:AMBER'],
  ['TLP', 'TLP:AMBER+STRICT'],
  ['TLP', 'TLP:RED'],
  ['PAP', 'PAP:CLEAR'],
  ['PAP', 'PAP:GREEN'],
  ['PAP', 'PAP:AMBER'],
  ['PAP', 'PAP:RED'],
];
export const BUILT_IN_MARKING_STANDARD_IDS = BUILT_IN_MARKINGS.map(([definitionType, definition]) => markingStandardId(definitionType, definition));

export const BUILT_IN_MARKING_REASON = 'Built-in marking';
const ORDER_REASON = 'The order of the marking changes';
const AUTO_NEW_MARKING_REASON = 'Groups that get new markings automatically get this one';

const refused = (status: 'failed' | 'skipped', code: MarkingImportCode, reason: string, exists: boolean, configuration?: MarkingImportConfiguration): MarkingImportResult => {
  return { status, code, reason, exists, configuration };
};

const hasAutoNewMarkingGroups = async (context: AuthContext, user: AuthUser) => {
  return (await findAllGroups(context, user, { filters: booleanTrueFilter('auto_new_marking') })).length > 0;
};

export const importMarking = async (
  context: AuthContext,
  user: AuthUser,
  configuration: unknown,
  { mode, dryRun = false }: ConfigImportOptions,
): Promise<MarkingImportResult> => {
  const parsed = markingImportSchema.safeParse(configuration);
  if (!parsed.success) {
    return refused('failed', 'invalid', configImportValidationReason(parsed.error), false);
  }
  const { definition_type: definitionType, definition, x_opencti_color: color, x_opencti_order: order } = parsed.data;
  const standardId = markingStandardId(definitionType, definition);
  if (BUILT_IN_MARKING_STANDARD_IDS.includes(standardId)) {
    return refused('skipped', 'built_in', BUILT_IN_MARKING_REASON, true, parsed.data);
  }
  const existing = await findById(context, user, standardId) as BasicStoreEntityMarking | undefined;
  if (existing && mode === ConfigImportMode.Add) {
    return refused('failed', 'exists', 'Marking already exists', true, parsed.data);
  }
  if (!(await isConfigImportSensitiveChangeAllowed(context, user, 'markings', standardId))) {
    return refused('failed', 'sensitive_config', CONFIG_IMPORT_SENSITIVE_REASON, !!existing, parsed.data);
  }
  if (existing) {
    const input: EditInput[] = ([['x_opencti_color', color], ['x_opencti_order', order]] as const)
      .filter(([key, value]) => value !== null && value !== undefined && value !== existing[key])
      .map(([key, value]) => ({ key, value: [value] }));
    if (input.length === 0) {
      return refused('skipped', 'unchanged', CONFIG_IMPORT_UNCHANGED_REASON, true, parsed.data);
    }
    const reason = joinConfigImportReasons([input.some(({ key }) => key === 'x_opencti_order') ? ORDER_REASON : undefined]);
    const result: MarkingImportResult = { status: 'overwritten', exists: true, configuration: parsed.data, reason };
    if (dryRun) {
      return result;
    }
    return { ...result, marking: await markingDefinitionEditField(context, user, existing.id, input) as BasicStoreEntityMarking };
  }
  const reason = joinConfigImportReasons([(await hasAutoNewMarkingGroups(context, user)) ? AUTO_NEW_MARKING_REASON : undefined]);
  const result: MarkingImportResult = { status: 'created', exists: false, configuration: parsed.data, reason };
  if (dryRun) {
    return result;
  }
  const marking = await addAllowedMarkingDefinition(context, user, {
    definition_type: definitionType,
    definition,
    x_opencti_order: order ?? 0,
    ...(color ? { x_opencti_color: color } : {}),
  });
  return { ...result, marking: marking as BasicStoreEntityMarking };
};
