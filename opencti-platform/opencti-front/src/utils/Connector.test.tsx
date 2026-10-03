import { describe, expect, it } from 'vitest';
import { Connector, useGetConnectorAvailableFilterKeys } from './Connector';
import { createMockUserContext, testRenderHook } from './tests/test-render';
import { FilterDefinition } from './hooks/useAuth';

const baseConnector: Connector = {
  name: 'test-connector',
  active: true,
  auto: false,
  only_contextual: false,
  connector_trigger_filters: '',
  connector_type: 'INTERNAL_ENRICHMENT',
  connector_scope: [],
  connector_state: '',
};

// Minimal schema fixture with one stixFilters-eligible key ('entity_type'), one SSVC key
// (now part of stixFilters), and one non-stix key that must always be filtered out.
const buildFilterKeysSchema = () => {
  const filterKeysSchema = new Map<string, Map<string, FilterDefinition>>();
  filterKeysSchema.set('Stix-Core-Object', new Map([
    ['entity_type', { filterKey: 'entity_type', type: 'string', label: 'Entity type', multiple: true, subEntityTypes: ['Stix-Core-Object'], elementsForFilterValuesSearch: [] } as unknown as FilterDefinition],
    ['x_opencti_ssvc_exploitation', { filterKey: 'x_opencti_ssvc_exploitation', type: 'string', label: 'SSVC Exploitation', multiple: false, subEntityTypes: ['Stix-Core-Object'], elementsForFilterValuesSearch: [] } as unknown as FilterDefinition],
    ['not_a_stix_filter', { filterKey: 'not_a_stix_filter', type: 'string', label: 'Not a stix filter', multiple: false, subEntityTypes: ['Stix-Core-Object'], elementsForFilterValuesSearch: [] } as unknown as FilterDefinition],
  ]));
  filterKeysSchema.set('Stix-Filtering', new Map());
  return filterKeysSchema;
};

describe('useGetConnectorAvailableFilterKeys', () => {
  it('should return an empty array when the connector is not an internal enrichment connector', () => {
    const connector: Connector = { ...baseConnector, connector_type: 'INTERNAL_IMPORT_FILE' };
    const { hook } = testRenderHook(
      () => useGetConnectorAvailableFilterKeys(connector),
      {
        userContext: createMockUserContext({
          schema: { scrs: [], sdos: [], scos: [], smos: [], filterKeysSchema: buildFilterKeysSchema() },
        }),
      },
    );
    expect(hook.result.current).toEqual([]);
  });

  it('should include the stix filter keys, including SSVC, and exclude non-stix keys', () => {
    const { hook } = testRenderHook(
      () => useGetConnectorAvailableFilterKeys(baseConnector),
      {
        userContext: createMockUserContext({
          schema: { scrs: [], sdos: [], scos: [], smos: [], filterKeysSchema: buildFilterKeysSchema() },
        }),
      },
    );
    expect(hook.result.current).toContain('entity_type');
    expect(hook.result.current).toContain('x_opencti_ssvc_exploitation');
    expect(hook.result.current).not.toContain('not_a_stix_filter');
  });
});
