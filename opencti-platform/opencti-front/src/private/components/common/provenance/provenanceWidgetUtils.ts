import type { WidgetDataSelection, WidgetPerspective } from '../../../../utils/widget/widget';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { computeWidgetFiltersForSelection } from '../../../../components/dashboard/dashboardVizUtils';

export const PROVENANCE_ENTITY_TYPES = ['Stix-Core-Object'];
export const PROVENANCE_RELATIONSHIP_TYPES = ['stix-core-relationship', 'stix-sighting-relationship'];

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
