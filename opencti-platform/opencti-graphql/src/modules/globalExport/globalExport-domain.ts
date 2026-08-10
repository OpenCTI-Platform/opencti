import { ZipArchive } from 'archiver';
import pjson from '../../../package.json';
import type { AuthContext, AuthUser } from '../../types/user';
import { BYPASS, isUserHasCapability } from '../../utils/access';
import { ForbiddenAccess } from '../../config/errors';
import { fullEntitiesList } from '../../database/middleware-loader';
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

const slugify = (name: string) => (name ?? 'unnamed')
  .toLowerCase()
  .replace(/[^a-z0-9-_]+/g, '-')
  .replace(/^-+|-+$/g, '')
  .slice(0, 80) || 'unnamed';

const exportEntitiesToZip = async <T extends { id: string; name: string }>(
  archive: ZipArchive,
  entities: T[],
  exportFn: (entity: T) => Promise<string>,
  pathFor: (entity: T) => string,
): Promise<number> => {
  for (let i = 0; i < entities.length; i += 1) {
    const exported = await exportFn(entities[i]);
    archive.append(exported, { name: pathFor(entities[i]) });
  }
  return entities.length;
};

export const exportPlaybooksCategory = async (context: AuthContext, user: AuthUser, archive: ZipArchive): Promise<number> => {
  const playbooks = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_PLAYBOOK], {});
  return exportEntitiesToZip(archive, playbooks, playbookExport, (p) => `playbooks/playbook-${slugify(p.name)}-${p.id}.json`);
};

export const exportFormsCategory = async (context: AuthContext, user: AuthUser, archive: ZipArchive): Promise<number> => {
  const forms = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_FORM], {});
  return exportEntitiesToZip(archive, forms, generateFormExportConfiguration, (f) => `form_intakes/form-${slugify(f.name)}-${f.id}.json`);
};

export const exportDashboardsCategory = async (context: AuthContext, user: AuthUser, archive: ZipArchive): Promise<number> => {
  const workspaces = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_WORKSPACE], {});
  const dashboards = workspaces.filter((w) => w.type === 'dashboard');
  return exportEntitiesToZip(
    archive,
    dashboards,
    (d) => generateWorkspaceExportConfiguration(context, user, d),
    (d) => `dashboards/dash-${slugify(d.name)}-${d.id}.json`,
  );
};

export const exportCustomViewsCategory = async (context: AuthContext, user: AuthUser, archive: ZipArchive): Promise<number> => {
  const customViews = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_CUSTOM_VIEW], {});
  return exportEntitiesToZip(
    archive,
    customViews,
    (cv) => exportCustomView(context, user, cv),
    (cv) => `custom_views/custom-view-${slugify(cv.name)}-${cv.id}.json`,
  );
};

export const exportFintelTemplatesCategory = async (context: AuthContext, user: AuthUser, archive: ZipArchive): Promise<number> => {
  const templates = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_FINTEL_TEMPLATE], {});
  return exportEntitiesToZip(
    archive,
    templates,
    (t) => fintelTemplateExport(context, user, t),
    (t) => `fintel_templates/fintel-template-${slugify(t.name)}-${t.id}.json`,
  );
};

export const exportIngestionCsvCategory = async (context: AuthContext, user: AuthUser, archive: ZipArchive): Promise<number> => {
  const feeds = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_INGESTION_CSV], {});
  return exportEntitiesToZip(
    archive,
    feeds,
    (f) => csvFeedMapperExport(context, user, f),
    (f) => `ingestion/feeds/feed-csv/feed-csv-${slugify(f.name)}-${f.id}.json`,
  );
};

export const exportIngestionJsonCategory = async (context: AuthContext, user: AuthUser, archive: ZipArchive): Promise<number> => {
  const feeds = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_INGESTION_JSON], {});
  return exportEntitiesToZip(
    archive,
    feeds,
    (f) => jsonFeedExport(context, user, f),
    (f) => `ingestion/feeds/feed-json/feed-json-${slugify(f.name)}-${f.id}.json`,
  );
};

export const exportIngestionRssCategory = async (context: AuthContext, user: AuthUser, archive: ZipArchive): Promise<number> => {
  const feeds = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_INGESTION_RSS], {});
  return exportEntitiesToZip(
    archive,
    feeds,
    (f) => rssFeedExport(context, user, f),
    (f) => `ingestion/feeds/feed-rss/feed-rss-${slugify(f.name)}-${f.id}.json`,
  );
};

export const exportIngestionTaxiiCategory = async (context: AuthContext, user: AuthUser, archive: ZipArchive): Promise<number> => {
  const feeds = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_INGESTION_TAXII], {});
  return exportEntitiesToZip(
    archive,
    feeds,
    taxiiFeedExport,
    (f) => `ingestion/feeds/feed-taxii/feed-taxii-${slugify(f.name)}-${f.id}.json`,
  );
};

export const exportCategory = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  archive: ZipArchive,
): Promise<number> => {
  switch (entityType) {
    case ENTITY_TYPE_PLAYBOOK: return exportPlaybooksCategory(context, user, archive);
    case ENTITY_TYPE_FORM: return exportFormsCategory(context, user, archive);
    case ENTITY_TYPE_WORKSPACE: return exportDashboardsCategory(context, user, archive);
    case ENTITY_TYPE_CUSTOM_VIEW: return exportCustomViewsCategory(context, user, archive);
    case ENTITY_TYPE_FINTEL_TEMPLATE: return exportFintelTemplatesCategory(context, user, archive);
    case ENTITY_TYPE_INGESTION_CSV: return exportIngestionCsvCategory(context, user, archive);
    case ENTITY_TYPE_INGESTION_JSON: return exportIngestionJsonCategory(context, user, archive);
    case ENTITY_TYPE_INGESTION_RSS: return exportIngestionRssCategory(context, user, archive);
    case ENTITY_TYPE_INGESTION_TAXII: return exportIngestionTaxiiCategory(context, user, archive);
    default: throw Error(`Unknown configuration export entity_type: "${entityType}"`);
  }
};

/**
 * Builds the configuration export ZIP for the given entity_types and returns it base64-encoded
 */
export const generateGlobalConfigurationExport = async (
  context: AuthContext,
  user: AuthUser,
  entityTypes: string[],
): Promise<string> => {
  if (!isUserHasCapability(user, BYPASS)) {
    throw ForbiddenAccess();
  }

  const archive = new ZipArchive();
  const chunks: Buffer[] = [];
  archive.on('data', (chunk: Buffer) => chunks.push(chunk));

  const counts: Record<string, number> = {};
  const uniqueEntityTypes = Array.from(new Set(entityTypes));

  for (let i = 0; i < uniqueEntityTypes.length; i += 1) {
    const entityType = uniqueEntityTypes[i];
    counts[entityType] = await exportCategory(context, user, entityType, archive);
  }

  const meta = {
    openCTI_version: pjson.version,
    generated_at: new Date().toISOString(),
    generated_by: user.id,
    entity_types: uniqueEntityTypes,
    counts,
  };
  archive.append(JSON.stringify(meta, null, 2), { name: 'meta.json' });

  await archive.finalize();
  const zipBuffer = Buffer.concat(chunks);
  return zipBuffer.toString('base64');
};
