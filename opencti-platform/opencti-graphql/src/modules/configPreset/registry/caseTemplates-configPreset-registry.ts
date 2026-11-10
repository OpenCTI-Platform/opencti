import { CaseTemplatesOrdering, FilterMode, FilterOperator, OrderingMode } from '../../../generated/graphql';
import { findAllCaseTemplates, findCaseTemplatePaginated } from '../../case/case-template/case-template-domain';
import { exportCaseTemplate } from '../../case/case-template/case-template-export';
import { importCaseTemplate } from '../../case/case-template/case-template-import';
import type { BasicStoreEntityCaseTemplate } from '../../case/case-template/case-template-types';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetImporter } from '../import/configPreset-import-types';
import { buildConfigPresetConnection, taxonomyGroup, toAppliedStatus, toComputedItem } from './common-configPreset-registry';

export const CASE_TEMPLATES_FAMILY_ID = 'caseTemplates';

const caseTemplatesArgs = (ids?: string[] | null, excludedIds?: string[] | null) => {
  const filters = [
    ...(ids ? [{ key: ['standard_id'], values: ids }] : []),
    ...(excludedIds && excludedIds.length > 0 ? [{ key: ['standard_id'], values: excludedIds, operator: FilterOperator.NotEq }] : []),
  ];
  return {
    orderBy: CaseTemplatesOrdering.Name,
    orderMode: OrderingMode.Asc,
    filters: { mode: FilterMode.And, filters, filterGroups: [] },
  };
};

// The bundle id of a case template is its standard id, which is random: the same template has another one on every platform.
// It only tells the items of a bundle apart: a template is found on the platform that imports it by its name.
const toCaseTemplateItem = (template: BasicStoreEntityCaseTemplate): ConfigPresetItemDefinition => ({
  id: template.standard_id,
  label: template.name,
  translatable: false,
  exporter: async (context, user) => exportCaseTemplate(context, user, template),
});

const caseTemplatesImporter: ConfigPresetImporter = {
  compute: async (context, user, item, _plan, mode) => {
    const { name } = item.configuration;
    const label = { label: typeof name === 'string' ? name.trim() : item.id, translatable: false };
    return toComputedItem(label, await importCaseTemplate(context, user, item.configuration, { mode, dryRun: true }));
  },
  // A template and its tasks are several writes: an item that fails can leave the task templates it created
  apply: async (context, user, item, computed, mode) => {
    return toAppliedStatus(await importCaseTemplate(context, user, item.configuration, { mode }), computed);
  },
};

// Case templates with their tasks, paged and searched through the case template domain. A template has no copy, an import overwrites.
export const caseTemplatesFamily: ConfigPresetFamilyDefinition = {
  importer: caseTemplatesImporter,
  id: CASE_TEMPLATES_FAMILY_ID,
  label: 'Case templates',
  description: 'Case templates and their tasks',
  group: taxonomyGroup,
  directory: 'taxonomy/case_templates',
  listItems: async (context, user, args) => {
    const { first, after, search, ids, excludedIds } = args;
    // An empty list of ids is no template: as a filter value it would match every template
    if (ids?.length === 0) {
      return buildConfigPresetConnection(args, [], 0, false);
    }
    const page = await findCaseTemplatePaginated(context, user, { first, after, search, ...caseTemplatesArgs(ids, excludedIds) });
    const edges = page.edges.map(({ cursor, node }) => ({ cursor, node: toCaseTemplateItem(node) }));
    return buildConfigPresetConnection(args, edges, page.pageInfo.globalCount, page.pageInfo.hasNextPage);
  },
  resolveItems: async (context, user, ids, excludedIds) => {
    if (ids?.length === 0) {
      return [];
    }
    return (await findAllCaseTemplates(context, user, caseTemplatesArgs(ids, excludedIds))).map(toCaseTemplateItem);
  },
};
