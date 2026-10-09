import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { ZipArchive } from 'archiver';
import pjson from '../../../package.json';
import type { AuthContext, AuthUser } from '../../types/user';
import { BYPASS, isUserHasCapability } from '../../utils/access';
import { ForbiddenAccess } from '../../config/errors';
import { logApp } from '../../config/conf';
import { fullEntitiesList } from '../../database/middleware-loader';
import { deleteFile, type LoadedFile, uploadToStorage } from '../../database/file-storage';
import { GLOBAL_EXPORT_STORAGE_PATH } from '../internal/document/document-types';
import { allFilesForPaths } from '../internal/document/document-domain';
import { ENTITY_TYPE_PLAYBOOK } from '../playbook/playbook-types';
import { playbookExport } from '../playbook/playbook-domain';
import { ENTITY_TYPE_FORM } from '../form/form-types';
import { generateFormExportConfiguration } from '../form/form-domain';
import { ENTITY_TYPE_WORKSPACE } from '../workspace/workspace-types';
import { generateWorkspaceExportConfiguration } from '../workspace/workspace-domain';
import { ENTITY_TYPE_CUSTOM_VIEW } from '../customView/customView-types';
import { exportCustomView } from '../customView/customView-domain';
import { ENTITY_TYPE_INGESTION_CSV, ENTITY_TYPE_INGESTION_JSON, ENTITY_TYPE_INGESTION_RSS, ENTITY_TYPE_INGESTION_TAXII } from '../ingestion/ingestion-types';
import { csvFeedMapperExport } from '../ingestion/ingestion-csv-domain';
import { jsonFeedExport } from '../ingestion/ingestion-json-domain';
import { rssFeedExport } from '../ingestion/ingestion-rss-domain';
import { taxiiFeedExport } from '../ingestion/ingestion-taxii-domain';
import { ENTITY_TYPE_FINTEL_TEMPLATE } from '../fintelTemplate/fintelTemplate-types';
import { fintelTemplateExport } from '../fintelTemplate/fintelTemplate-domain';
import {
  generateSettingsBrandingExportConfiguration,
  generateSettingsLanguageExportConfiguration,
  generateSettingsMessagesExportConfiguration,
  generateSettingsPoliciesExportConfiguration,
  generateSettingsThemeExportConfiguration,
} from '../../domain/settings';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_ROLE } from '../../schema/internalObject';
import { generateGroupExportConfiguration } from '../../domain/group';
import { generateRoleExportConfiguration } from '../user/user-domain';
import { generateHiddenEntityTypesExportConfiguration } from '../entitySetting/entitySetting-domain';
import { buildContextDataForFile, publishUserAction } from '../../listener/UserActionListener';
import { addGlobalExportPlatformCount } from '../../manager/telemetryManager';
import { type FilterGroup, FilterMode } from '../../generated/graphql';

const slugify = (name: string) => (name ?? 'unnamed')
  .toLowerCase()
  .replace(/[^a-z0-9-_]+/g, '-')
  .replace(/^-+|-+$/g, '')
  .slice(0, 80) || 'unnamed';

export const buildUniqueNamePath = (directory: string) => {
  const usedNames = new Set<string>();
  return (entity: { name: string }): string => {
    const baseName = slugify(entity.name);
    let name = baseName;
    let suffix = 2;
    while (usedNames.has(name)) {
      name = `${baseName}${suffix}`;
      suffix += 1;
    }
    usedNames.add(name);
    return `${directory}/${name}.json`;
  };
};

const buildIdFilterGroup = (ids?: string[]): FilterGroup | undefined => {
  if (!ids || ids.length === 0) {
    return undefined;
  }
  return {
    mode: FilterMode.Or,
    filters: [{ key: ['internal_id'], values: ids }],
    filterGroups: [],
  };
};

export const SETTINGS_THEME = 'SettingsTheme';
export const SETTINGS_LANGUAGE = 'SettingsLanguage';
export const SETTINGS_MESSAGES = 'SettingsMessages';
export const SETTINGS_HIDDEN_ENTITY_TYPES = 'SettingsHiddenEntityTypes';
export const SETTINGS_POLICIES = 'SettingsPolicies';

// Adds the export_id that the import will use to find an element that already exists on the target platform.
export const withExportId = (exported: string, entity: { export_id?: string }): string => {
  const { configuration, ...header } = JSON.parse(exported);
  return JSON.stringify({ ...header, export_id: entity.export_id, configuration });
};

const exportEntitiesToZip = async <T extends { id: string; export_id?: string; name: string }>(
  archive: ZipArchive,
  entities: T[],
  exportFn: (entity: T) => Promise<string>,
  pathFor: (entity: T) => string,
): Promise<number> => {
  for (let i = 0; i < entities.length; i += 1) {
    const exported = await exportFn(entities[i]);
    archive.append(withExportId(exported, entities[i]), { name: pathFor(entities[i]) });
  }
  return entities.length;
};

export const exportPlaybooksCategory = async (context: AuthContext, user: AuthUser, archive: ZipArchive, ids?: string[]): Promise<number> => {
  const playbooks = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_PLAYBOOK], { filters: buildIdFilterGroup(ids) });
  return exportEntitiesToZip(archive, playbooks, playbookExport, (p) => `automation/playbooks/playbook-${slugify(p.name)}-${p.id}.json`);
};

export const exportFormsCategory = async (context: AuthContext, user: AuthUser, archive: ZipArchive, ids?: string[]): Promise<number> => {
  const forms = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_FORM], { filters: buildIdFilterGroup(ids) });
  return exportEntitiesToZip(archive, forms, generateFormExportConfiguration, (f) => `ingestion/forms/form-${slugify(f.name)}-${f.id}.json`);
};

export const exportDashboardsCategory = async (context: AuthContext, user: AuthUser, archive: ZipArchive, ids?: string[]): Promise<number> => {
  // Only the id restriction is pushed to the ES query here; the "dashboard" sub-type filtering
  // stays in memory, exactly like in the pre-existing code, to keep this simple (no filter group nesting).
  const workspaces = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_WORKSPACE], { filters: buildIdFilterGroup(ids) });
  const dashboards = workspaces.filter((w) => w.type === 'dashboard');
  return exportEntitiesToZip(
    archive,
    dashboards,
    (d) => generateWorkspaceExportConfiguration(context, user, d),
    (d) => `visualization/custom_dashboards/dash-${slugify(d.name)}-${d.id}.json`,
  );
};

export const exportCustomViewsCategory = async (context: AuthContext, user: AuthUser, archive: ZipArchive, ids?: string[]): Promise<number> => {
  const customViews = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_CUSTOM_VIEW], { filters: buildIdFilterGroup(ids) });
  return exportEntitiesToZip(
    archive,
    customViews,
    (cv) => exportCustomView(context, user, cv),
    (cv) => `visualization/custom_views/custom-view-${slugify(cv.name)}-${cv.id}.json`,
  );
};

export const exportFintelTemplatesCategory = async (context: AuthContext, user: AuthUser, archive: ZipArchive, ids?: string[]): Promise<number> => {
  const templates = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_FINTEL_TEMPLATE], { filters: buildIdFilterGroup(ids) });
  return exportEntitiesToZip(
    archive,
    templates,
    (t) => fintelTemplateExport(context, user, t),
    (t) => `visualization/fintel_templates/fintel-template-${slugify(t.name)}-${t.id}.json`,
  );
};

export const exportIngestionCsvCategory = async (context: AuthContext, user: AuthUser, archive: ZipArchive, ids?: string[]): Promise<number> => {
  const feeds = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_INGESTION_CSV], { filters: buildIdFilterGroup(ids) });
  return exportEntitiesToZip(
    archive,
    feeds,
    (f) => csvFeedMapperExport(context, user, f),
    (f) => `ingestion/csv_feeds/feed-csv-${slugify(f.name)}-${f.id}.json`,
  );
};

export const exportIngestionJsonCategory = async (context: AuthContext, user: AuthUser, archive: ZipArchive, ids?: string[]): Promise<number> => {
  const feeds = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_INGESTION_JSON], { filters: buildIdFilterGroup(ids) });
  return exportEntitiesToZip(
    archive,
    feeds,
    (f) => jsonFeedExport(context, user, f),
    (f) => `ingestion/json_feeds/feed-json-${slugify(f.name)}-${f.id}.json`,
  );
};

export const exportIngestionRssCategory = async (context: AuthContext, user: AuthUser, archive: ZipArchive, ids?: string[]): Promise<number> => {
  const feeds = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_INGESTION_RSS], { filters: buildIdFilterGroup(ids) });
  return exportEntitiesToZip(
    archive,
    feeds,
    (f) => rssFeedExport(context, user, f),
    (f) => `ingestion/rss_feeds/feed-rss-${slugify(f.name)}-${f.id}.json`,
  );
};

export const exportIngestionTaxiiCategory = async (context: AuthContext, user: AuthUser, archive: ZipArchive, ids?: string[]): Promise<number> => {
  const feeds = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_INGESTION_TAXII], { filters: buildIdFilterGroup(ids) });
  return exportEntitiesToZip(
    archive,
    feeds,
    taxiiFeedExport,
    (f) => `ingestion/taxii_feeds/feed-taxii-${slugify(f.name)}-${f.id}.json`,
  );
};

export const exportGroupsCategory = async (context: AuthContext, user: AuthUser, archive: ZipArchive, ids?: string[]): Promise<number> => {
  const groups = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_GROUP], { filters: buildIdFilterGroup(ids) });
  return exportEntitiesToZip(
    archive,
    groups,
    (g) => generateGroupExportConfiguration(context, user, g),
    buildUniqueNamePath('security/groups'),
  );
};

export const exportRolesCategory = async (context: AuthContext, user: AuthUser, archive: ZipArchive, ids?: string[]): Promise<number> => {
  const roles = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_ROLE], { filters: buildIdFilterGroup(ids) });
  return exportEntitiesToZip(
    archive,
    roles,
    (r) => generateRoleExportConfiguration(context, user, r),
    buildUniqueNamePath('security/roles'),
  );
};

export const exportSettingsThemeCategory = async (context: AuthContext, _user: AuthUser, archive: ZipArchive): Promise<number> => {
  const exportedTheme = await generateSettingsThemeExportConfiguration(context);
  archive.append(exportedTheme, { name: 'parameters/theme/theme.json' });
  const exportedBranding = await generateSettingsBrandingExportConfiguration(context);
  archive.append(exportedBranding, { name: 'parameters/theme/branding.json' });
  return 2;
};

export const exportSettingsLanguageCategory = async (context: AuthContext, _user: AuthUser, archive: ZipArchive): Promise<number> => {
  const exported = await generateSettingsLanguageExportConfiguration(context);
  archive.append(exported, { name: 'parameters/language.json' });
  return 1;
};

export const exportSettingsMessagesCategory = async (context: AuthContext, _user: AuthUser, archive: ZipArchive): Promise<number> => {
  const exported = await generateSettingsMessagesExportConfiguration(context);
  archive.append(exported, { name: 'parameters/messages.json' });
  return 1;
};

export const exportSettingsPoliciesCategory = async (context: AuthContext, user: AuthUser, archive: ZipArchive): Promise<number> => {
  const exported = await generateSettingsPoliciesExportConfiguration(context, user);
  archive.append(exported, { name: 'security/policies.json' });
  return 1;
};

export const exportHiddenEntityTypesCategory = async (context: AuthContext, user: AuthUser, archive: ZipArchive): Promise<number> => {
  const exported = await generateHiddenEntityTypesExportConfiguration(context, user);
  archive.append(exported, { name: 'parameters/hidden_entity_types.json' });
  return JSON.parse(exported).configuration.hidden_entity_types.length;
};

export const exportCategory = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  archive: ZipArchive,
  ids?: string[],
): Promise<number> => {
  switch (entityType) {
    case ENTITY_TYPE_PLAYBOOK: return exportPlaybooksCategory(context, user, archive, ids);
    case ENTITY_TYPE_FORM: return exportFormsCategory(context, user, archive, ids);
    case ENTITY_TYPE_WORKSPACE: return exportDashboardsCategory(context, user, archive, ids);
    case ENTITY_TYPE_CUSTOM_VIEW: return exportCustomViewsCategory(context, user, archive, ids);
    case ENTITY_TYPE_FINTEL_TEMPLATE: return exportFintelTemplatesCategory(context, user, archive, ids);
    case ENTITY_TYPE_INGESTION_CSV: return exportIngestionCsvCategory(context, user, archive, ids);
    case ENTITY_TYPE_INGESTION_JSON: return exportIngestionJsonCategory(context, user, archive, ids);
    case ENTITY_TYPE_INGESTION_RSS: return exportIngestionRssCategory(context, user, archive, ids);
    case ENTITY_TYPE_INGESTION_TAXII: return exportIngestionTaxiiCategory(context, user, archive, ids);
    case ENTITY_TYPE_GROUP: return exportGroupsCategory(context, user, archive, ids);
    case ENTITY_TYPE_ROLE: return exportRolesCategory(context, user, archive, ids);
    case SETTINGS_THEME: return exportSettingsThemeCategory(context, user, archive);
    case SETTINGS_LANGUAGE: return exportSettingsLanguageCategory(context, user, archive);
    case SETTINGS_MESSAGES: return exportSettingsMessagesCategory(context, user, archive);
    case SETTINGS_POLICIES: return exportSettingsPoliciesCategory(context, user, archive);
    case SETTINGS_HIDDEN_ENTITY_TYPES: return exportHiddenEntityTypesCategory(context, user, archive);
    default: throw Error(`Unknown configuration export entity_type: "${entityType}"`);
  }
};

const GLOBAL_EXPORT_FILE_TTL_MS = 60 * 60 * 1000;

export const deleteGlobalExportsNotModifiedSince = async (context: AuthContext, user: AuthUser, notModifiedSince: Date): Promise<void> => {
  const expiredFiles = await allFilesForPaths(context, user, [GLOBAL_EXPORT_STORAGE_PATH], { notModifiedSince: notModifiedSince.toISOString() });
  for (let i = 0; i < expiredFiles.length; i += 1) {
    await deleteFile(context, user, expiredFiles[i].id, { forceDelete: true });
  }
};

/**
 * Builds the configuration export ZIP for the given entity_types and uploads it to the global export storage
 */
export const generateGlobalConfigurationExport = async (
  context: AuthContext,
  user: AuthUser,
  entityTypes: string[],
  selections?: { entityType: string; ids?: string[] | null }[] | null,
  bundleName?: string | null,
): Promise<LoadedFile> => {
  if (!isUserHasCapability(user, BYPASS)) {
    throw ForbiddenAccess();
  }
  addGlobalExportPlatformCount();

  await deleteGlobalExportsNotModifiedSince(context, user, new Date(Date.now() - GLOBAL_EXPORT_FILE_TTL_MS)).catch((err) => {
    logApp.warn('[GLOBAL EXPORT] Failed to remove expired export files', { cause: err });
  });

  const idsByEntityType = new Map<string, string[]>();
  (selections ?? []).forEach((selection) => {
    if (selection.ids && selection.ids.length > 0) {
      idsByEntityType.set(selection.entityType, selection.ids);
    }
  });

  const uniqueEntityTypes = Array.from(new Set(entityTypes));
  const tmpZipPath = path.join(os.tmpdir(), `opencti-global-export-${crypto.randomUUID()}.zip`);
  const archive = new ZipArchive();
  const writeStream = fs.createWriteStream(tmpZipPath);
  const zipReady = new Promise<void>((resolve, reject) => {
    writeStream.on('close', resolve);
    writeStream.on('error', reject);
    archive.on('error', reject);
  });
  zipReady.catch(() => {});
  archive.pipe(writeStream);

  try {
    const counts: Record<string, number> = {};
    const requestedCounts: Record<string, number> = {};

    for (let i = 0; i < uniqueEntityTypes.length; i += 1) {
      const entityType = uniqueEntityTypes[i];
      const requestedIds = idsByEntityType.get(entityType);
      if (requestedIds && requestedIds.length > 0) {
        requestedCounts[entityType] = requestedIds.length;
      }
      counts[entityType] = await exportCategory(context, user, entityType, archive, requestedIds);
    }

    const meta = {
      openCTI_version: pjson.version,
      generated_at: new Date().toISOString(),
      generated_by: user.id,
      entity_types: uniqueEntityTypes,
      counts,
      requested_counts: requestedCounts,
    };
    archive.append(JSON.stringify(meta), { name: 'meta.json' });

    await archive.finalize();
    await zipReady;

    const bundleSuffix = bundleName?.trim() ? `-${slugify(bundleName)}` : '';
    const filename = `opencti-config-${new Date().toISOString().replace(/[:.]/g, '-')}-${pjson.version}${bundleSuffix}.zip`;
    const { upload } = await uploadToStorage(
      context,
      user,
      GLOBAL_EXPORT_STORAGE_PATH,
      { createReadStream: () => fs.createReadStream(tmpZipPath), filename },
      { noTriggerImport: true, meta: { description: 'Global platform configuration export' } },
    );

    const contextData = buildContextDataForFile(
      null,
      'global_configuration_export',
      filename,
      [],
      { entity_types: uniqueEntityTypes, counts },
    );
    await publishUserAction({
      user,
      event_type: 'file',
      event_access: 'administration',
      event_scope: 'create',
      context_data: contextData,
    });

    return upload;
  } catch (error) {
    archive.abort();
    writeStream.destroy();
    // Wait for the write stream to be closed before removing the temporary file
    await zipReady.catch(() => {});
    throw error;
  } finally {
    await fs.promises.unlink(tmpZipPath).catch((err) => {
      logApp.warn('[GLOBAL EXPORT] Failed to remove temporary export file', { cause: err, tmpZipPath });
    });
  }
};
