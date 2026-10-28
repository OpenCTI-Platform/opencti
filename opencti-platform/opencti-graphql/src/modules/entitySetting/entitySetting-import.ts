import type { AuthContext, AuthUser } from '../../types/user';
import { fullEntitiesList } from '../../database/middleware-loader';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../configImport/configImport-types';
import { configImportValidationReason } from '../configImport/configImport-utils';
import { entitySettingsEditField } from './entitySetting-domain';
import { type HiddenEntityTypesImportConfiguration, hiddenEntityTypesImportSchema } from './entitySetting-import-schema';
import { ENTITY_TYPE_ENTITY_SETTING, type BasicStoreEntityEntitySetting } from './entitySetting-types';
import { getAvailableSettings } from './entitySetting-utils';

export type HiddenEntityTypesImportCode = 'invalid' | 'not_overwrite' | 'cannot_be_hidden' | 'nothing_to_import';

export type HiddenEntityTypesImportResult = ConfigImportResult<HiddenEntityTypesImportConfiguration, HiddenEntityTypesImportCode>;

const PLATFORM_HIDDEN_TYPE = 'platform_hidden_type';

// A type with an entity setting that does not offer the hiding (or that the platform does not support for entity settings) cannot be hidden
const canBeHidden = (type: string) => {
  try {
    return getAvailableSettings(type).includes(PLATFORM_HIDDEN_TYPE);
  } catch {
    return false;
  }
};

const refused = (
  status: 'failed' | 'skipped',
  code: HiddenEntityTypesImportCode,
  reason: string,
  configuration?: HiddenEntityTypesImportConfiguration,
): HiddenEntityTypesImportResult => ({ status, code, reason, exists: true, configuration });

// The entity types hidden for the whole platform become the ones of the configuration: the listed types are hidden, and the types
// hidden now that are not listed are shown again. Every type is checked before any is written: a type of the configuration that this
// platform does not know, or cannot hide, refuses all of it. It always exists, and has no copy, so only an overwrite writes it.
// A dry run decides the same result and writes nothing.
export const importHiddenEntityTypes = async (
  context: AuthContext,
  user: AuthUser,
  configuration: unknown,
  { mode, dryRun = false }: ConfigImportOptions,
): Promise<HiddenEntityTypesImportResult> => {
  const parsed = hiddenEntityTypesImportSchema.safeParse(configuration);
  if (!parsed.success) {
    return refused('failed', 'invalid', configImportValidationReason(parsed.error));
  }
  if (mode !== ConfigImportMode.Overwrite) {
    return refused('skipped', 'not_overwrite', 'Already exists', parsed.data);
  }
  const wanted = new Set(parsed.data.hidden_entity_types);
  const entitySettings = await fullEntitiesList<BasicStoreEntityEntitySetting>(context, user, [ENTITY_TYPE_ENTITY_SETTING]);
  const settingOf = new Map(entitySettings.map((entitySetting) => [entitySetting.target_type, entitySetting]));
  const cannotBeHidden = [...wanted].filter((type) => !settingOf.has(type) || !canBeHidden(type)).sort();
  if (cannotBeHidden.length > 0) {
    return refused('failed', 'cannot_be_hidden', `Entity types that cannot be hidden: ${cannotBeHidden.join(', ')}`, parsed.data);
  }
  const toHide = entitySettings.filter((entitySetting) => wanted.has(entitySetting.target_type) && !entitySetting.platform_hidden_type);
  const toShow = entitySettings.filter((entitySetting) => !wanted.has(entitySetting.target_type) && entitySetting.platform_hidden_type);
  if (toHide.length === 0 && toShow.length === 0) {
    return refused('skipped', 'nothing_to_import', 'Nothing to import', parsed.data);
  }
  if (!dryRun) {
    if (toHide.length > 0) {
      await entitySettingsEditField(context, user, toHide.map(({ id }) => id), [{ key: PLATFORM_HIDDEN_TYPE, value: [true] }]);
    }
    if (toShow.length > 0) {
      await entitySettingsEditField(context, user, toShow.map(({ id }) => id), [{ key: PLATFORM_HIDDEN_TYPE, value: [false] }]);
    }
  }
  return { status: 'overwritten', exists: true, configuration: parsed.data };
};
