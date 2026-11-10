import type { AuthContext, AuthUser } from '../../../types/user';
import { ConfigImportMode } from '../../configImport/configImport-types';
import { freeConfigImportName } from '../../configImport/configImport-utils';
import { BUILT_IN_MARKING_STANDARD_IDS } from '../../markingDefinition/marking-import';
import type { FeedKind } from '../../ingestion/ingestion-import';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetComputedItem, ConfigPresetImporter, ConfigPresetImportPlan } from '../import/configPreset-import-types';
import { configPresetPlanKey } from '../import/configPreset-import-types';
import { buildConfigPresetConnection, integrationsGroup, MARKINGS_FAMILY_ID, toAppliedStatus, toComputedItem } from './common-configPreset-registry';

export const RSS_FEEDS_FAMILY_ID = 'rssFeeds';
export const CSV_FEEDS_FAMILY_ID = 'csvFeeds';
export const JSON_FEEDS_FAMILY_ID = 'jsonFeeds';
export const TAXII_FEEDS_FAMILY_ID = 'taxiiFeeds';

// The feed domains load the whole schema: they are loaded on first use, so that importing the registry stays light
const loadFeedImport = () => import('../../ingestion/ingestion-import');
const loadFeedExport = () => import('../../ingestion/ingestion-export');

const fileNameOf = (id: string) => id.replace(/[^\p{L}\p{N} ._()-]/gu, '_');

// Feed names are not unique: the bundle id of a feed is its name, and the next feeds of the same name are `name (1)`, `name (2)`... by creation date
const feedItems = async (context: AuthContext, user: AuthUser, kind: FeedKind): Promise<ConfigPresetItemDefinition[]> => {
  const [{ feedAdapterOf }, { exportFeedMarkingIds }] = await Promise.all([loadFeedImport(), loadFeedExport()]);
  const adapter = feedAdapterOf(kind);
  const feeds = [...await adapter.list(context, user)]
    .sort((a, b) => String(a.created_at).localeCompare(String(b.created_at)) || String(a.internal_id).localeCompare(String(b.internal_id)));
  const ids = new Set<string>();
  const fileNames = new Set<string>();
  const items: ConfigPresetItemDefinition[] = [];
  for (let i = 0; i < feeds.length; i += 1) {
    const feed = feeds[i];
    const id = await freeConfigImportName(feed.name, async (candidate) => ids.has(candidate));
    if (id) {
      ids.add(id);
      const fileName = (await freeConfigImportName(fileNameOf(id), async (candidate) => fileNames.has(candidate))) ?? id;
      fileNames.add(fileName);
      const markingIds = await exportFeedMarkingIds(context, user, feed);
      items.push({
        id,
        label: feed.name,
        translatable: false,
        fileName: `${fileName}.json`,
        dependsOn: markingIds
          .filter((standardId) => !BUILT_IN_MARKING_STANDARD_IDS.includes(standardId))
          .map((standardId) => ({ type: MARKINGS_FAMILY_ID, id: standardId })),
        exporter: async (ctx, usr) => adapter.exportFeed(ctx, usr, feed),
      });
    }
  }
  return items.sort((a, b) => a.label.localeCompare(b.label) || a.id.localeCompare(b.id));
};

const reservedNamesOf = (plan: ConfigPresetImportPlan, familyId: string) => {
  plan.ingestionFeedNames ??= new Map();
  const names = plan.ingestionFeedNames.get(familyId) ?? new Set<string>();
  plan.ingestionFeedNames.set(familyId, names);
  return names;
};

const feedImporter = (familyId: string, kind: FeedKind): ConfigPresetImporter => {
  const itemOptionsOf = (plan: ConfigPresetImportPlan, id: string) => ({
    credentials: plan.credentials?.get(configPresetPlanKey(familyId, id)),
    serviceAccountId: plan.serviceAccounts?.get(configPresetPlanKey(familyId, id)),
  });
  return {
    compute: async (context, user, item, plan, mode): Promise<ConfigPresetComputedItem> => {
      const { name } = item.configuration;
      const label = { label: typeof name === 'string' && name.trim() ? name : item.id, translatable: false };
      const reservedNames = reservedNamesOf(plan, familyId);
      const options = {
        mode,
        dryRun: true,
        reservedNames,
        ingestionGroupPlanned: plan.ingestionGroupPlanned,
        plannedMarkings: plan.plannedMarkings,
        ...itemOptionsOf(plan, item.id),
      };
      const { feedAdapterOf, importConfigPresetFeed } = await loadFeedImport();
      const result = await importConfigPresetFeed(context, user, feedAdapterOf(kind), item.configuration, options);
      if (result.status !== 'failed' && result.name) {
        reservedNames.add(result.name);
      }
      if (result.status === 'created' && !result.exists) {
        plan.created.add(configPresetPlanKey(familyId, item.id));
      }
      return { ...toComputedItem(label, result), credentials: result.credentials };
    },
    apply: async (context, user, item, computed, mode, plan) => {
      const { feedAdapterOf, importConfigPresetFeed } = await loadFeedImport();
      return toAppliedStatus(await importConfigPresetFeed(context, user, feedAdapterOf(kind), item.configuration, { mode, ...itemOptionsOf(plan, item.id) }), computed);
    },
  };
};

const feedFamily = (
  kind: FeedKind,
  family: Pick<ConfigPresetFamilyDefinition, 'id' | 'label' | 'description' | 'directory'>,
): ConfigPresetFamilyDefinition => ({
  ...family,
  importer: feedImporter(family.id, kind),
  importModes: [ConfigImportMode.Overwrite, ConfigImportMode.Copy],
  group: integrationsGroup,
  listItems: async (context, user, args) => {
    const { first, after, search, ids, excludedIds } = args;
    const searched = search?.trim().toLowerCase();
    const items = (await feedItems(context, user, kind))
      .filter((item) => (!ids || ids.includes(item.id)) && !(excludedIds ?? []).includes(item.id))
      .filter((item) => !searched || item.label.toLowerCase().includes(searched));
    const start = after ? items.findIndex((item) => item.id === after) + 1 : 0;
    const page = first ? items.slice(start, start + first) : items.slice(start);
    return buildConfigPresetConnection(args, page.map((node) => ({ node, cursor: node.id })), items.length, start + page.length < items.length);
  },
  resolveItems: async (context, user, ids, excludedIds) => {
    return (await feedItems(context, user, kind)).filter((item) => (!ids || ids.includes(item.id)) && !excludedIds.includes(item.id));
  },
});

export const rssFeedsFamily = feedFamily('rss', {
  id: RSS_FEEDS_FAMILY_ID,
  label: 'RSS feeds',
  description: 'RSS feeds and their parameters, without their state',
  directory: 'integrations/rss_feeds',
});
export const csvFeedsFamily = feedFamily('csv', {
  id: CSV_FEEDS_FAMILY_ID,
  label: 'CSV feeds',
  description: 'CSV feeds with their mapper, without their credentials',
  directory: 'integrations/csv_feeds',
});
export const jsonFeedsFamily = feedFamily('json', {
  id: JSON_FEEDS_FAMILY_ID,
  label: 'JSON feeds',
  description: 'JSON feeds with their mapper, without their credentials',
  directory: 'integrations/json_feeds',
});
export const taxiiFeedsFamily = feedFamily('taxii', {
  id: TAXII_FEEDS_FAMILY_ID,
  label: 'TAXII feeds',
  description: 'TAXII feeds and their parameters, without their credentials',
  directory: 'integrations/taxii_feeds',
});
