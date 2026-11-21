import * as R from 'ramda';
import slugify from 'slug';
import { GraphQLError } from 'graphql';
import { FUNCTIONAL_ERROR } from '../../config/errors';
import { FilterMode, type EditInput } from '../../generated/graphql';
import { fullEntitiesList } from '../../database/middleware-loader';
import { addCustomViewCreatedCount } from '../../manager/telemetryManager';
import { createInternalObject, editInternalObject } from '../../domain/internalObject';
import type { AuthContext, AuthUser } from '../../types/user';
import { fromB64 } from '../../utils/base64';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../configImport/configImport-types';
import {
  CONFIG_IMPORT_UNCHANGED_REASON,
  configImportReasonValue,
  configImportRefusal,
  configImportValidationReason,
  freeConfigImportName,
} from '../configImport/configImport-utils';
import { convertDashboardManifestIds } from '../dashboard/dashboard-utils';
import { sanitizeCustomViewManifest } from '../workspace/workspace-variables-utils';
import { isCustomViewsAvailableForEntityType } from './customView-domain';
import { CUSTOM_VIEW_NAME_MAX_LENGTH, type CustomViewImportConfiguration, customViewImportSchema } from './customView-import-schema';
import { type BasicStoreEntityCustomView, ENTITY_TYPE_CUSTOM_VIEW, type StoreEntityCustomView } from './customView-types';

// The custom views the earlier items of the same dry run take, written or not, by `customViewImportKey`: the view of a name is imported once
// per import. An overwrite reserves the name it targets, a copy the name it takes
export interface CustomViewImportOptions extends ConfigImportOptions {
  reservedNames?: Set<string>;
}

export type CustomViewImportCode = 'invalid' | 'entity_type' | 'exists' | 'unchanged' | 'ambiguous' | 'duplicate' | 'name_conflict';

export type CustomViewImportResult = ConfigImportResult<CustomViewImportConfiguration, CustomViewImportCode>;

const refused = configImportRefusal<CustomViewImportConfiguration, CustomViewImportCode>;

// The identity of a custom view: the same name can be taken by the views of two entity types
export const customViewImportKey = (targetEntityType: string, name: string) => `${targetEntityType}/${name}`;

export const findCustomViewsByName = async (context: AuthContext, user: AuthUser, targetEntityType: string, name: string) => {
  const customViews = await fullEntitiesList<BasicStoreEntityCustomView>(context, user, [ENTITY_TYPE_CUSTOM_VIEW], {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['target_entity_type'], values: [targetEntityType] }, { key: ['name'], values: [name] }],
      filterGroups: [],
    },
  });
  // The filter on the name does not tell the case apart
  return customViews.filter((customView) => customView.name === name);
};

// The manifest with the ids of this platform. A reference it does not have is kept as it is, as the file import does.
// Refused, as on every way into a custom view, when a widget uses dashboard variables
const prepareManifest = async (context: AuthContext, user: AuthUser, manifest: string | null | undefined) => {
  if (!manifest) {
    return undefined;
  }
  return convertDashboardManifestIds(context, user, sanitizeCustomViewManifest(manifest), 'stix') as Promise<string>;
};

const auditLogContextSanitizer = <T extends Record<string, unknown>>(element: T) => ({ ...element, manifest: '[sanitized]' });

// region writes
// Created as the file import does: neither enabled nor the default of its entity type, which is for the platform that imports it to decide
const createCustomView = async (context: AuthContext, user: AuthUser, data: CustomViewImportConfiguration, manifest: string | undefined, name: string) => {
  const created = await createInternalObject<StoreEntityCustomView>(
    context,
    user,
    {
      ...R.reject(R.isNil, { description: data.description, manifest }),
      name,
      slug: slugify(name),
      target_entity_type: data.target_entity_type,
      enabled: false,
      default: false,
    },
    ENTITY_TYPE_CUSTOM_VIEW,
    { auditLogEnabled: true, auditLogContextSanitizer },
  );
  addCustomViewCreatedCount();
  return created;
};

// The fields an import writes on an existing custom view: what the bundle sets and the view does not have. A value that is null or absent leaves
// the one of the view untouched. Its name and entity type are its identity, and whether it is enabled or the default is never touched
const buildPatch = (existing: BasicStoreEntityCustomView, data: CustomViewImportConfiguration, manifest: string | undefined) => {
  const patch: EditInput[] = [];
  if (data.description != null && data.description !== (existing.description ?? '')) patch.push({ key: 'description', value: [data.description] });
  if (manifest && !R.equals(fromB64(existing.manifest), fromB64(manifest))) patch.push({ key: 'manifest', value: [manifest] });
  return patch;
};
// endregion

// The one place where a custom view is imported from a configuration bundle: validates, finds the view by its entity type and its name and writes it.
// A refusal is a result, not an error. A dry run decides the same result and writes nothing.
// The standard id of a custom view is random, so its entity type and its name are its identity: add refuses an existing one, overwrite patches the view
// that has them (its description and its manifest; whether it is enabled or the default is kept), else creates it. A name that several views of the
// entity type have is refused.
// Copy creates the view under a free name (`name (1)`, ...), whether the name is taken or not.
// A view that an earlier item of the same import already took is a duplicate: refused, as the later item would overwrite the view of the earlier one.
// A view is never enabled nor the default when it is created, a copy included.
// The ids of the filters are converted to this platform's: a reference it does not have is kept as it is, as the file import does.
export const importCustomView = async (
  context: AuthContext,
  user: AuthUser,
  configuration: unknown,
  { mode, dryRun = false, reservedNames }: CustomViewImportOptions,
): Promise<CustomViewImportResult> => {
  const parsed = customViewImportSchema.safeParse(configuration);
  if (!parsed.success) {
    return refused('failed', 'invalid', configImportValidationReason(parsed.error), false);
  }
  const { data } = parsed;
  // The entity types of a platform are not the ones of another (a newer version, a module not deployed): the item fails, the others go on
  if (!isCustomViewsAvailableForEntityType(data.target_entity_type)) {
    return refused('failed', 'entity_type', 'Custom views cannot be created for this entity type', false, data);
  }
  let manifest: string | undefined;
  try {
    manifest = await prepareManifest(context, user, data.manifest);
  } catch (error) {
    // Only what the manifest breaks is a refusal of the item: a failure of the platform (a lookup of the ids that times out) stays an error
    if (!(error instanceof GraphQLError && error.extensions.code === FUNCTIONAL_ERROR)) {
      throw error;
    }
    return refused('failed', 'invalid', configImportReasonValue(error.message), false, data);
  }
  const { name, target_entity_type: targetEntityType } = data;
  if (mode === ConfigImportMode.Copy) {
    const sameName = await findCustomViewsByName(context, user, targetEntityType, name);
    // The name of the configuration is read once: the first candidate of a copy is that name
    const isTaken = async (candidate: string) => {
      if (reservedNames?.has(customViewImportKey(targetEntityType, candidate))) {
        return true;
      }
      return (candidate === name ? sameName : await findCustomViewsByName(context, user, targetEntityType, candidate)).length > 0;
    };
    const copyName = await freeConfigImportName(name, isTaken, { maxLength: CUSTOM_VIEW_NAME_MAX_LENGTH });
    if (!copyName) {
      return refused('failed', 'name_conflict', 'Custom view name already exists', sameName.length > 0, data);
    }
    if (dryRun) {
      reservedNames?.add(customViewImportKey(targetEntityType, copyName));
    } else {
      await createCustomView(context, user, data, manifest, copyName);
    }
    const reason = copyName === name ? undefined : `Added as "${configImportReasonValue(copyName)}"`;
    return { status: 'created', exists: sameName.length > 0, configuration: data, reason };
  }
  const key = customViewImportKey(targetEntityType, name);
  if (reservedNames?.has(key)) {
    // exists is false: the clash is with an earlier item of the bundle, not with a view of the platform, so the preview offers no choice
    return refused('failed', 'duplicate', 'Another custom view of the import has this name', false, data);
  }
  if (dryRun) {
    reservedNames?.add(key);
  }
  const sameName = await findCustomViewsByName(context, user, targetEntityType, name);
  if (sameName.length > 1) {
    return refused('failed', 'ambiguous', 'Several custom views have this name', true, data);
  }
  const [existing] = sameName;
  if (!existing) {
    if (!dryRun) {
      await createCustomView(context, user, data, manifest, name);
    }
    return { status: 'created', exists: false, configuration: data };
  }
  if (mode === ConfigImportMode.Add) {
    return refused('failed', 'exists', 'Custom view already exists', true, data);
  }
  const patch = buildPatch(existing, data, manifest);
  if (patch.length === 0) {
    return refused('skipped', 'unchanged', CONFIG_IMPORT_UNCHANGED_REASON, true, data);
  }
  if (!dryRun) {
    await editInternalObject<StoreEntityCustomView>(
      context,
      user,
      existing.id,
      ENTITY_TYPE_CUSTOM_VIEW,
      patch,
      {
        auditLogEnabled: true,
        auditLogContextSanitizer: (input) => input.map((entry) => ({ ...entry, value: entry.key === 'manifest' ? ['[sanitized]'] : entry.value })),
      },
    );
  }
  return { status: 'overwritten', exists: true, configuration: data };
};
