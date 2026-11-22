import type { ComponentDefinition } from '../playbook/playbook-types';
import { PLAYBOOK_DATA_STREAM_REQUIREMENT_ID, type RequirementStreamConfiguration } from '../playbook/components/data-stream-requirement-component';

// Pure part of the Pir migration (no database access, unit tested): the rewrite of a playbook definition whose entry is
// "Listen PIR events" into "Listen intelligence requirement events", the Pir ids replaced by the ids of their requirements.

export const PLAYBOOK_DATA_STREAM_PIR_ID = 'PLAYBOOK_DATA_STREAM_PIR';

export interface PlaybookRewrite {
  definition: string;
  changed: boolean;
  // Pir ids of an entry node that no requirement replaces (a Pir kept after a failed conversion, or already gone)
  unmapped: string[];
}

interface LegacyPirStreamConfiguration {
  create?: boolean;
  create_rel?: boolean;
  update?: boolean;
  delete?: boolean;
  inPirFilters?: unknown;
  filters?: string;
}

const pirFilterValues = (inPirFilters: unknown) => {
  if (!Array.isArray(inPirFilters)) return [];
  return inPirFilters
    .map((item: unknown) => (item && typeof item === 'object' && 'value' in item ? { value: (item as { value: unknown }).value, label: (item as { label?: unknown }).label } : null))
    .filter((item): item is { value: string; label: unknown } => !!item && typeof item.value === 'string' && item.value.length > 0);
};

/**
 * A playbook definition with every "Listen PIR events" entry turned into "Listen intelligence requirement events". Pure.
 * The node keeps its id, name, position and links, so playbook_start and the rest of the graph are untouched; its
 * toggles and source filters are kept as they are; inPirFilters becomes requirementFilters with the requirement ids.
 * An entry naming a Pir no requirement replaces is left unchanged and the playbook is reported (never half rewritten).
 */
export const rewritePlaybookDefinition = (definition: string, requirementOfPir: Map<string, string>): PlaybookRewrite => {
  let parsed: ComponentDefinition;
  try {
    parsed = JSON.parse(definition) as ComponentDefinition;
  } catch {
    return { definition, changed: false, unmapped: [] };
  }
  if (!parsed || !Array.isArray(parsed.nodes)) return { definition, changed: false, unmapped: [] };
  const entries = parsed.nodes.filter((node) => node.component_id === PLAYBOOK_DATA_STREAM_PIR_ID);
  if (entries.length === 0) return { definition, changed: false, unmapped: [] };
  const unmapped = new Set<string>();
  const nodes = parsed.nodes.map((node) => {
    if (node.component_id !== PLAYBOOK_DATA_STREAM_PIR_ID) return node;
    let legacy: LegacyPirStreamConfiguration;
    try {
      legacy = JSON.parse(node.configuration ?? '{}') as LegacyPirStreamConfiguration;
    } catch {
      legacy = {};
    }
    const requirementFilters = pirFilterValues(legacy.inPirFilters).map((pir) => {
      const requirementId = requirementOfPir.get(pir.value);
      if (!requirementId) {
        unmapped.add(pir.value);
        return { value: pir.value };
      }
      return typeof pir.label === 'string' ? { value: requirementId, label: pir.label } : { value: requirementId };
    });
    const { inPirFilters: _dropped, ...rest } = legacy;
    const configuration: RequirementStreamConfiguration = {
      create: legacy.create ?? true,
      create_rel: legacy.create_rel ?? false,
      update: legacy.update ?? false,
      delete: legacy.delete ?? false,
      filters: legacy.filters ?? '',
      ...rest,
      requirementFilters,
    } as RequirementStreamConfiguration;
    return { ...node, component_id: PLAYBOOK_DATA_STREAM_REQUIREMENT_ID, configuration: JSON.stringify(configuration) };
  });
  if (unmapped.size > 0) return { definition, changed: false, unmapped: Array.from(unmapped) };
  return { definition: JSON.stringify({ ...parsed, nodes }), changed: true, unmapped: [] };
};
