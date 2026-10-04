import type { WidgetDataSelection, WidgetPerspective } from '../../../../utils/widget/widget';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { computeWidgetFiltersForSelection } from '../../../../components/dashboard/dashboardVizUtils';

export const PROVENANCE_ENTITY_TYPES = ['Stix-Core-Object'];
export const PROVENANCE_RELATIONSHIP_TYPES = ['stix-core-relationship', 'stix-sighting-relationship'];

// Why a provenance widget is empty
export const PROVENANCE_WIDGET_NO_DATA = 'No assertion recorded yet. Provenance appears as connectors and users create knowledge.';
// Shown instead of a provenance widget saved on a dashboard while provenance is disabled on the platform
export const PROVENANCE_WIDGET_DISABLED = 'Provenance is disabled on this platform.';
export const PROVENANCE_WIDGET_DISABLED_NEXT_STEP = 'An administrator enables it in the platform configuration (provenance:enabled).';
export const PROVENANCE_CONFIGURATION_DOCUMENTATION = 'https://docs.opencti.io/latest/usage/provenance/#configuration';

export const PROVENANCE_WIDGET_TITLES: Record<string, string> = {
  'provenance-freshness': 'Knowledge freshness - days since the last assertion',
  'provenance-single-sourced': 'Single-sourced share by entity type',
};
export const PROVENANCE_WIDGET_TYPES = Object.keys(PROVENANCE_WIDGET_TITLES);
export const isProvenanceWidget = (type: string) => PROVENANCE_WIDGET_TYPES.includes(type);

/**
 * Query variables of the provenance widgets: the knowledge of the widget perspective, narrowed by the
 * filters and the dashboard dates of its data selection.
 */
export const buildProvenanceWidgetVariables = (
  perspective: WidgetPerspective,
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
) => {
  const isRelationships = perspective === 'relationships';
  const { filters } = computeWidgetFiltersForSelection(resolvedDataSelection[0], config, { isKnowledgeRelationshipWidget: isRelationships });
  return {
    types: isRelationships ? PROVENANCE_RELATIONSHIP_TYPES : PROVENANCE_ENTITY_TYPES,
    filters,
  };
};
