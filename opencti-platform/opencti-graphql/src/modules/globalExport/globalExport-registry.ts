import { fullEntitiesList } from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';

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

export interface GlobalExportEntry {
  key: string; // must match item.key in the front's PlatformBundleDrawer.utils.ts
  entityType: string;
  // Folder path inside the ZIP where this category's entity files are written.
  folder: string;
  // Filename prefix for each entity file (e.g. 'dash', 'playbook', 'feed-csv').
  filePrefix: string;
  listAll: (context: AuthContext, user: AuthUser) => Promise<any[]>;
  // Returns the JSON STRING already produced by the existing *Export function
  exportOne: (context: AuthContext, user: AuthUser, entity: any) => Promise<string>;
}

const listAllOfType = (entityType: string) => async (context: AuthContext, user: AuthUser) => {
  return fullEntitiesList<any>(context, user, [entityType], {});
};

/**
 * ⚠️ Single source of truth for the export orchestrator. Each `key` MUST
 * match an item.key declared in the front's `PlatformBundleDrawer.utils.ts`
 * (EXPORT_CATEGORIES). Every category produces ONE FILE PER ENTITY inside
 * its own `folder` - no more "collection" (single aggregated file) layout.
 * Categories with no export function yet (platform, security, taxonomies,
 * custom_attributes, workflows, saved_searches, email_templates,
 * exclusion_lists, rule_engine, connectors, streams) are intentionally
 * NOT listed here - tracked for V1/V2.
 */
export const GLOBAL_EXPORT_REGISTRY: GlobalExportEntry[] = [
  {
    key: 'custom_views',
    entityType: ENTITY_TYPE_CUSTOM_VIEW,
    folder: 'custom_views',
    filePrefix: 'custom-view',
    listAll: listAllOfType(ENTITY_TYPE_CUSTOM_VIEW),
    exportOne: async (context, user, customView) => exportCustomView(context, user, customView),
  },
  {
    key: 'form_intakes',
    entityType: ENTITY_TYPE_FORM,
    folder: 'form_intakes',
    filePrefix: 'form',
    listAll: listAllOfType(ENTITY_TYPE_FORM),
    exportOne: async (_c, _u, form) => generateFormExportConfiguration(form),
  },
  {
    key: 'dashboards',
    entityType: ENTITY_TYPE_WORKSPACE,
    folder: 'dashboards',
    filePrefix: 'dash',
    listAll: async (context, user) => {
      const workspaces = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_WORKSPACE], {});
      return workspaces.filter((w) => w.type === 'dashboard');
    },
    exportOne: async (context, user, workspace) => generateWorkspaceExportConfiguration(context, user, workspace),
  },
  {
    key: 'playbooks',
    entityType: ENTITY_TYPE_PLAYBOOK,
    folder: 'playbooks',
    filePrefix: 'playbook',
    listAll: listAllOfType(ENTITY_TYPE_PLAYBOOK),
    exportOne: async (_c, _u, playbook) => playbookExport(playbook),
  },
  {
    key: 'fintel_templates',
    entityType: ENTITY_TYPE_FINTEL_TEMPLATE,
    folder: 'fintel_templates',
    filePrefix: 'fintel-template',
    listAll: listAllOfType(ENTITY_TYPE_FINTEL_TEMPLATE),
    exportOne: async (context, user, template) => fintelTemplateExport(context, user, template),
  },
  {
    key: 'feeds_csv',
    entityType: ENTITY_TYPE_INGESTION_CSV,
    folder: 'ingestion/feeds/feed-csv',
    filePrefix: 'feed-csv',
    listAll: listAllOfType(ENTITY_TYPE_INGESTION_CSV),
    exportOne: async (context, user, ingestionCsv) => csvFeedMapperExport(context, user, ingestionCsv),
  },
  {
    key: 'feeds_json',
    entityType: ENTITY_TYPE_INGESTION_JSON,
    folder: 'ingestion/feeds/feed-json',
    filePrefix: 'feed-json',
    listAll: listAllOfType(ENTITY_TYPE_INGESTION_JSON),
    exportOne: async (context, user, ingestionJson) => jsonFeedExport(context, user, ingestionJson),
  },
  {
    key: 'feeds_rss',
    entityType: ENTITY_TYPE_INGESTION_RSS,
    folder: 'ingestion/feeds/feed-rss',
    filePrefix: 'feed-rss',
    listAll: listAllOfType(ENTITY_TYPE_INGESTION_RSS),
    exportOne: async (context, user, ingestionRss) => rssFeedExport(context, user, ingestionRss),
  },
  {
    key: 'feeds_taxii',
    entityType: ENTITY_TYPE_INGESTION_TAXII,
    folder: 'ingestion/feeds/feed-taxii',
    filePrefix: 'feed-taxii',
    listAll: listAllOfType(ENTITY_TYPE_INGESTION_TAXII),
    exportOne: async (_c, _u, ingestionTaxii) => taxiiFeedExport(ingestionTaxii),
  },
];

export const getGlobalExportEntry = (key: string): GlobalExportEntry => {
  const entry = GLOBAL_EXPORT_REGISTRY.find((e) => e.key === key);
  if (!entry) {
    throw Error(`Unknown configuration export key: "${key}" - no export function registered for it.`);
  }
  return entry;
};
