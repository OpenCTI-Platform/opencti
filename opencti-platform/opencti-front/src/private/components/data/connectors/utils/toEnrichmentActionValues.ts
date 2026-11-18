import type { EnrichmentConnector } from '../EnrichmentConnectorSelection';

/**
 * The values of an ENRICHMENT background task action: the given connectors, or only those selected
 * by id, in the order they were selected. Each is given as `{ id, value }`: the launcher shows the
 * connector name and sends only its id. A selected id missing from the connectors keeps its id as name.
 */
const toEnrichmentActionValues = (
  connectors: readonly EnrichmentConnector[],
  selectedIds: readonly string[] = connectors.map((connector) => connector.id),
) => selectedIds.map((id) => ({
  id,
  value: connectors.find((connector) => connector.id === id)?.name ?? id,
}));

export default toEnrichmentActionValues;
