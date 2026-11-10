import { FilterMode, FilterOperator, OrderingMode, StatusTemplateOrdering } from '../../../generated/graphql';
import { ConfigImportMode } from '../../configImport/configImport-types';
import { findAllStatusTemplates, findTemplatePaginated } from '../../../domain/status';
import { exportStatusTemplate } from '../../statusTemplate/statusTemplate-export';
import { getStatusTemplateStandardId, importStatusTemplate } from '../../statusTemplate/statusTemplate-import';
import type { BasicStoreEntityStatusTemplate } from '../../statusTemplate/statusTemplate-types';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetImporter } from '../import/configPreset-import-types';
import { buildConfigPresetConnection, checkStandardId, taxonomyGroup, toAppliedStatus, toComputedItem } from './common-configPreset-registry';

export const STATUS_TEMPLATES_FAMILY_ID = 'statusTemplates';

const statusTemplatesArgs = (ids?: string[] | null, excludedIds?: string[] | null) => {
  const filters = [
    ...(ids ? [{ key: ['standard_id'], values: ids }] : []),
    ...(excludedIds && excludedIds.length > 0 ? [{ key: ['standard_id'], values: excludedIds, operator: FilterOperator.NotEq }] : []),
  ];
  return {
    orderBy: StatusTemplateOrdering.Name,
    orderMode: OrderingMode.Asc,
    filters: { mode: FilterMode.And, filters, filterGroups: [] },
  };
};

// A template is identified by its standard id everywhere: derived from its name, it is the same on every platform
const toStatusTemplateItem = (template: BasicStoreEntityStatusTemplate): ConfigPresetItemDefinition => ({
  id: template.standard_id,
  label: template.name,
  translatable: false,
  exporter: async () => exportStatusTemplate(template),
});

const statusTemplatesImporter: ConfigPresetImporter = {
  compute: async (context, user, item, _plan, mode) => {
    const { name } = item.configuration;
    const label = { label: typeof name === 'string' ? name.trim() : item.id, translatable: false };
    // The bundle id of a status template is its standard id: the one of its name
    const mismatch = checkStandardId(item, label, [name], ([templateName]) => getStatusTemplateStandardId(templateName.trim()), 'The standard id of the status template does not match its name');
    if (mismatch) {
      return mismatch;
    }
    return toComputedItem(label, await importStatusTemplate(context, user, item.configuration, { mode, dryRun: true }));
  },
  apply: async (context, user, item, computed, mode) => {
    return toAppliedStatus(await importStatusTemplate(context, user, item.configuration, { mode }), computed);
  },
};

// Status templates: all of them, the ones the platform creates included (an import finds them by their name and skips the ones that are
// the same), paged and searched through the status domain. An import overwrites, or adds a copy under a free name.
export const statusTemplatesFamily: ConfigPresetFamilyDefinition = {
  importer: statusTemplatesImporter,
  importModes: [ConfigImportMode.Overwrite, ConfigImportMode.Copy],
  id: STATUS_TEMPLATES_FAMILY_ID,
  label: 'Status templates',
  description: 'Status templates and their colors',
  group: taxonomyGroup,
  directory: 'taxonomy/status_templates',
  listItems: async (context, user, args) => {
    const { first, after, search, ids, excludedIds } = args;
    // An empty list of ids is no template: as a filter value it would match every template
    if (ids?.length === 0) {
      return buildConfigPresetConnection(args, [], 0, false);
    }
    const page = await findTemplatePaginated(context, user, { first, after, search, ...statusTemplatesArgs(ids, excludedIds) });
    const edges = page.edges.map(({ cursor, node }) => ({ cursor, node: toStatusTemplateItem(node as BasicStoreEntityStatusTemplate) }));
    return buildConfigPresetConnection(args, edges, page.pageInfo.globalCount, page.pageInfo.hasNextPage);
  },
  resolveItems: async (context, user, ids, excludedIds) => {
    if (ids?.length === 0) {
      return [];
    }
    return (await findAllStatusTemplates(context, user, statusTemplatesArgs(ids, excludedIds))).map(toStatusTemplateItem);
  },
};
