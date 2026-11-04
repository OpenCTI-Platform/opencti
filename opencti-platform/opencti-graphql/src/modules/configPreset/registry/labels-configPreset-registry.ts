import { FilterMode, FilterOperator, LabelsOrdering, OrderingMode } from '../../../generated/graphql';
import { findAllLabels, findLabelPaginated } from '../../../domain/label';
import { exportLabel } from '../../label/label-export';
import { getLabelStandardId, importLabel } from '../../label/label-import';
import type { BasicStoreEntityLabel } from '../../label/label-types';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetImporter } from '../import/configPreset-import-types';
import { buildConfigPresetConnection, taxonomyGroup, toAppliedStatus, toComputedItem, checkStandardId } from './common-configPreset-registry';

export const LABELS_FAMILY_ID = 'labels';

const labelsArgs = (ids?: string[] | null, excludedIds?: string[] | null) => {
  const filters = [
    ...(ids ? [{ key: ['standard_id'], values: ids }] : []),
    ...(excludedIds && excludedIds.length > 0 ? [{ key: ['standard_id'], values: excludedIds, operator: FilterOperator.NotEq }] : []),
  ];
  return {
    orderBy: LabelsOrdering.Value,
    orderMode: OrderingMode.Asc,
    filters: { mode: FilterMode.And, filters, filterGroups: [] },
  };
};

// A label is identified by its standard id everywhere: derived from its value, it is the same on every platform
const toLabelItem = (label: BasicStoreEntityLabel): ConfigPresetItemDefinition => ({
  id: label.standard_id,
  label: label.value,
  translatable: false,
  exporter: async () => exportLabel(label),
});

const labelsImporter: ConfigPresetImporter = {
  compute: async (context, user, item, _plan, mode) => {
    const value = typeof item.configuration.value === 'string' ? item.configuration.value.trim() : item.id;
    const label = { label: value, translatable: false };
    // The bundle id of a label is its standard id: the one of its value
    const mismatch = checkStandardId(item, label, [item.configuration.value], ([labelValue]) => getLabelStandardId(labelValue), 'The standard id of the label does not match its value');
    if (mismatch) {
      return mismatch;
    }
    return toComputedItem(label, await importLabel(context, user, item.configuration, { mode, dryRun: true }));
  },
  apply: async (context, user, item, computed, mode) => {
    return toAppliedStatus(await importLabel(context, user, item.configuration, { mode }), computed);
  },
};

// Labels: paged and searched through the label domain. A label has no copy, an import overwrites.
export const labelsFamily: ConfigPresetFamilyDefinition = {
  importer: labelsImporter,
  id: LABELS_FAMILY_ID,
  label: 'Labels',
  description: 'Labels and their colors',
  group: taxonomyGroup,
  directory: 'taxonomy/labels',
  listItems: async (context, user, args) => {
    const { first, after, search, ids, excludedIds } = args;
    // An empty list of ids is no label: as a filter value it would match every label
    if (ids?.length === 0) {
      return buildConfigPresetConnection(args, [], 0, false);
    }
    const page = await findLabelPaginated(context, user, { first, after, search, ...labelsArgs(ids, excludedIds) });
    const edges = page.edges.map(({ cursor, node }: { cursor: string; node: BasicStoreEntityLabel }) => ({ cursor, node: toLabelItem(node) }));
    return buildConfigPresetConnection(args, edges, page.pageInfo.globalCount, page.pageInfo.hasNextPage);
  },
  resolveItems: async (context, user, ids, excludedIds) => {
    if (ids?.length === 0) {
      return [];
    }
    const labels: BasicStoreEntityLabel[] = await findAllLabels(context, user, labelsArgs(ids, excludedIds));
    return labels.map(toLabelItem);
  },
};
