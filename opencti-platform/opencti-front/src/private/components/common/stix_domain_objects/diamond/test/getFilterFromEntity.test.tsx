import { describe, it, expect } from 'vitest';
import getFilterFromEntityTypeAndNodeType, { DiamondEntityType, DiamondNodeType } from '@components/common/stix_domain_objects/diamond/getFilterFromEntityTypeAndNodeType';

describe('get the filters from Threat-actor-group, containing a diamond ', () => {
  const entityType = 'Threat-Actor-Group' as DiamondEntityType;
  it('should list filter for adversary', () => {
    const nodeType = 'adversary' as DiamondNodeType;
    const expectedFilters = {
      mode: 'and',
      filters: [
        {
          key: 'entity_type',
          operator: 'eq',
          values: [
            'Campaign',
            'Intrusion-Set',
            'Incident',
          ],
          mode: 'or',
        },
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'relationship_type',
              values: [
                'attributed-to',
              ],
            },
          ],
          mode: 'or',
        },
      ],
      filterGroups: [],
    };
    const encodedFilters = encodeURIComponent(JSON.stringify(expectedFilters));
    const results = getFilterFromEntityTypeAndNodeType(entityType, nodeType);
    expect(results).toEqual(encodedFilters);
  });
  it('should list filter for infrastructure', () => {
    const nodeType = 'infrastructure' as DiamondNodeType;
    const expectedFilters = {
      mode: 'and',
      filters: [
        {
          key: 'entity_type',
          operator: 'eq',
          values: [
            'IPv4-Addr',
            'IPv6-Addr',
            'Infrastructure',
            'Domain-Name',
          ],
          mode: 'or',
        },
        {
          key: 'regardingOf',
          operator: 'eq',
          values: [
            {
              key: 'relationship_type',
              values: [
                'uses',
                'hosts',
                'owns',
                'related-to',
              ],
            },
          ],
          mode: 'or',
        },
      ],
      filterGroups: [],
    };
    const encodedFilters = encodeURIComponent(JSON.stringify(expectedFilters));
    const results = getFilterFromEntityTypeAndNodeType(entityType, nodeType);
    expect(results).toEqual(encodedFilters);
  });
});
