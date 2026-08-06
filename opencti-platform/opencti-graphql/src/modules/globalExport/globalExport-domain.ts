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

const exportCategory = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  archive: ZipArchive,
): Promise<number> => {
  if (entityType === ENTITY_TYPE_PLAYBOOK) {
    const playbooks = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_PLAYBOOK], {});
    for (let i = 0; i < playbooks.length; i += 1) {
      const exported = await playbookExport(playbooks[i]);
      archive.append(exported, { name: `playbooks/playbook-${slugify(playbooks[i].name)}-${playbooks[i].id}.json` });
    }
    return playbooks.length;
  }

  if (entityType === ENTITY_TYPE_FORM) {
    const forms = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_FORM], {});
    for (let i = 0; i < forms.length; i += 1) {
      const exported = await generateFormExportConfiguration(forms[i]);
      archive.append(exported, { name: `form_intakes/form-${slugify(forms[i].name)}-${forms[i].id}.json` });
    }
    return forms.length;
  }

  if (entityType === ENTITY_TYPE_WORKSPACE) {
    const workspaces = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_WORKSPACE], {});
    const dashboards = workspaces.filter((w) => w.type === 'dashboard');
    for (let i = 0; i < dashboards.length; i += 1) {
      const exported = await generateWorkspaceExportConfiguration(context, user, dashboards[i]);
      archive.append(exported, { name: `dashboards/dash-${slugify(dashboards[i].name)}-${dashboards[i].id}.json` });
    }
    return dashboards.length;
  }

  if (entityType === ENTITY_TYPE_CUSTOM_VIEW) {
    const customViews = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_CUSTOM_VIEW], {});
    for (let i = 0; i < customViews.length; i += 1) {
      const exported = await exportCustomView(context, user, customViews[i]);
      archive.append(exported, { name: `custom_views/custom-view-${slugify(customViews[i].name)}-${customViews[i].id}.json` });
    }
    return customViews.length;
  }

  if (entityType === ENTITY_TYPE_FINTEL_TEMPLATE) {
    const templates = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_FINTEL_TEMPLATE], {});
    for (let i = 0; i < templates.length; i += 1) {
      const exported = await fintelTemplateExport(context, user, templates[i]);
      archive.append(exported, { name: `fintel_templates/fintel-template-${slugify(templates[i].name)}-${templates[i].id}.json` });
    }
    return templates.length;
  }

  if (entityType === ENTITY_TYPE_INGESTION_CSV) {
    const feeds = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_INGESTION_CSV], {});
    for (let i = 0; i < feeds.length; i += 1) {
      const exported = await csvFeedMapperExport(context, user, feeds[i]);
      archive.append(exported, { name: `ingestion/feeds/feed-csv/feed-csv-${slugify(feeds[i].name)}-${feeds[i].id}.json` });
    }
    return feeds.length;
  }

  if (entityType === ENTITY_TYPE_INGESTION_JSON) {
    const feeds = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_INGESTION_JSON], {});
    for (let i = 0; i < feeds.length; i += 1) {
      const exported = await jsonFeedExport(context, user, feeds[i]);
      archive.append(exported, { name: `ingestion/feeds/feed-json/feed-json-${slugify(feeds[i].name)}-${feeds[i].id}.json` });
    }
    return feeds.length;
  }

  if (entityType === ENTITY_TYPE_INGESTION_RSS) {
    const feeds = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_INGESTION_RSS], {});
    for (let i = 0; i < feeds.length; i += 1) {
      const exported = await rssFeedExport(context, user, feeds[i]);
      archive.append(exported, { name: `ingestion/feeds/feed-rss/feed-rss-${slugify(feeds[i].name)}-${feeds[i].id}.json` });
    }
    return feeds.length;
  }

  if (entityType === ENTITY_TYPE_INGESTION_TAXII) {
    const feeds = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_INGESTION_TAXII], {});
    for (let i = 0; i < feeds.length; i += 1) {
      const exported = await taxiiFeedExport(feeds[i]);
      archive.append(exported, { name: `ingestion/feeds/feed-taxii/feed-taxii-${slugify(feeds[i].name)}-${feeds[i].id}.json` });
    }
    return feeds.length;
  }

  throw Error(`Unknown configuration export entity_type: "${entityType}"`);
};

/**
 * Builds the configuration export ZIP for the given entity_types and returns
 * it base64-encoded, following the same pattern as a single-entity export
 * function (returns a string) - the frontend decodes it and triggers the
 * browser download.
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
