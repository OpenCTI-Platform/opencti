import { FilterMode, FilterOperator, OrderingMode } from '../../../generated/graphql';
import { fullEntitiesList, pageEntitiesConnection } from '../../../database/middleware-loader';
import { ENTITY_TYPE_CONNECTOR } from '../../../schema/internalObject';
import { ConfigImportMode } from '../../configImport/configImport-types';
import { exportConnector } from '../../connector/connector-export';
import { importConnector, loadConnectorImportContext } from '../../connector/connector-import';
import type { BasicStoreEntityConnector } from '../../connector/connector-types';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetComputedItem, ConfigPresetImporter } from '../import/configPreset-import-types';
import { configPresetPlanKey } from '../import/configPreset-import-types';
import { buildConfigPresetConnection, integrationsGroup, toAppliedStatus, toComputedItem } from './common-configPreset-registry';

export const CONNECTORS_FAMILY_ID = 'connectors';

// Only the connectors deployed from the platform through the connector manager: a connector registered from outside has no configuration here
const connectorsArgs = (ids?: string[] | null, excludedIds?: string[] | null) => ({
  orderBy: 'name',
  orderMode: OrderingMode.Asc,
  filters: {
    mode: FilterMode.And,
    filters: [
      { key: ['catalog_id'], values: ['EXISTS'] },
      ...(ids ? [{ key: ['name'], values: ids }] : []),
      ...(excludedIds && excludedIds.length > 0 ? [{ key: ['name'], values: excludedIds, operator: FilterOperator.NotEq }] : []),
    ],
    filterGroups: [],
  },
  noFiltersChecking: true,
});

const toConnectorItem = (connector: BasicStoreEntityConnector): ConfigPresetItemDefinition => ({
  id: connector.name,
  label: connector.title ?? connector.name,
  translatable: false,
  exporter: async (context) => exportConnector(context, connector),
});

type Plan = Parameters<ConfigPresetImporter['compute']>[3];
const itemOptionsOf = (plan: Plan, id: string) => ({
  bundleId: id,
  credentials: plan.credentials?.get(configPresetPlanKey(CONNECTORS_FAMILY_ID, id)),
  serviceAccountId: plan.serviceAccounts?.get(configPresetPlanKey(CONNECTORS_FAMILY_ID, id)),
});

const connectorsImporter: ConfigPresetImporter = {
  compute: async (context, user, item, plan, mode): Promise<ConfigPresetComputedItem> => {
    const { name } = item.configuration;
    const title = typeof name === 'string' && name.trim() ? name : undefined;
    const label = { label: title ?? item.id, translatable: false };
    plan.connectorsLoaded ??= loadConnectorImportContext(context, user);
    const loaded = await plan.connectorsLoaded;
    const options = { mode, dryRun: true, loaded, reservedNames: plan.connectorNames, ingestionGroupPlanned: plan.ingestionGroupPlanned, ...itemOptionsOf(plan, item.id) };
    const result = await importConnector(context, user, item.configuration, options);
    if (result.status === 'created' && !result.exists) {
      plan.created.add(configPresetPlanKey(CONNECTORS_FAMILY_ID, item.id));
    }
    return { ...toComputedItem(label, result), credentials: result.credentials };
  },
  apply: async (context, user, item, computed, mode, plan) => {
    return toAppliedStatus(await importConnector(context, user, item.configuration, { mode, ...itemOptionsOf(plan, item.id) }), computed);
  },
};

export const connectorsFamily: ConfigPresetFamilyDefinition = {
  importer: connectorsImporter,
  importModes: [ConfigImportMode.Overwrite, ConfigImportMode.Copy],
  requiresEnterpriseEdition: true,
  id: CONNECTORS_FAMILY_ID,
  label: 'Connectors',
  description: 'Managed connectors and their parameters, without their secrets',
  group: integrationsGroup,
  directory: 'integrations/connectors',
  listItems: async (context, user, args) => {
    const { first, after, search, ids, excludedIds } = args;
    if (ids?.length === 0) {
      return buildConfigPresetConnection(args, [], 0, false);
    }
    const page = await pageEntitiesConnection<BasicStoreEntityConnector>(context, user, [ENTITY_TYPE_CONNECTOR], { first, after, search, ...connectorsArgs(ids, excludedIds) });
    const edges = page.edges.map(({ cursor, node }) => ({ cursor, node: toConnectorItem(node) }));
    return buildConfigPresetConnection(args, edges, page.pageInfo.globalCount, page.pageInfo.hasNextPage);
  },
  resolveItems: async (context, user, ids, excludedIds) => {
    if (ids?.length === 0) {
      return [];
    }
    return (await fullEntitiesList<BasicStoreEntityConnector>(context, user, [ENTITY_TYPE_CONNECTOR], connectorsArgs(ids, excludedIds))).map(toConnectorItem);
  },
};
