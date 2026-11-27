import { FilterMode, FilterOperator, LabelsOrdering, OrderingMode } from '../../../generated/graphql';
import { elRefreshIndices } from '../../../database/engine';
import { READ_INDEX_STIX_META_OBJECTS } from '../../../database/utils';
import { internalFindByIds } from '../../../database/middleware-loader';
import { findAllLabels, findLabelPaginated } from '../../../domain/label';
import { ENTITY_TYPE_LABEL } from '../../../schema/stixMetaObject';
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

// The ids of the lookup are the standard ids of the bundle: one query for a slice of the items, never one per label
const LABELS_PREPARE_SIZE = 1000;

const labelsImporter: ConfigPresetImporter = {
  prepare: async (context, user, items, plan) => {
    const existing = plan.existingLabels ?? new Map<string, BasicStoreEntityLabel>();
    const ids = items.map((item) => item.id);
    for (let i = 0; i < ids.length; i += LABELS_PREPARE_SIZE) {
      const labels = await internalFindByIds(context, user, ids.slice(i, i + LABELS_PREPARE_SIZE), { type: ENTITY_TYPE_LABEL }) as unknown as BasicStoreEntityLabel[];
      labels.forEach((label) => existing.set(label.standard_id, label));
      plan.onPrepared?.(Math.min(i + LABELS_PREPARE_SIZE, ids.length), ids.length);
    }
    plan.existingLabels = existing;
  },
  compute: async (context, user, item, plan, mode) => {
    const value = typeof item.configuration.value === 'string' ? item.configuration.value.trim() : item.id;
    const label = { label: value, translatable: false };
    // The bundle id of a label is its standard id: the one of its value
    const mismatch = checkStandardId(item, label, [item.configuration.value], ([labelValue]) => getLabelStandardId(labelValue), 'The standard id of the label does not match its value');
    if (mismatch) {
      return mismatch;
    }
    return toComputedItem(label, await importLabel(context, user, item.configuration, { mode, dryRun: true }, plan.existingLabels));
  },
  apply: async (context, user, item, computed, mode, plan) => {
    // The labels read ahead by prepare, when the caller did: no lookup per label (the partial import has none, it looks the label up)
    return toAppliedStatus(await importLabel(context, user, item.configuration, { mode, deferRefresh: plan.deferRefresh }, plan.existingLabels), computed);
  },
  // The labels of a real import were written without a refresh of their index: one refresh makes them all searchable
  finalize: async () => {
    await elRefreshIndices([READ_INDEX_STIX_META_OBJECTS]);
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
