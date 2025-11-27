import { describe, it, expect } from 'vitest';
import getFilterFromEntityTypeAndNodeType from '@components/common/stix_domain_objects/diamond/getFilterFromEntityTypeAndNodeType';
import { DiamondEntityEnum, DiamondNodeEnum } from '../types/nodes/diamondEnums';

describe('get the filters from Threat-actor-group, containing a diamond ', () => {
  const entityType = DiamondEntityEnum.threatActorGroup;

  it('should list filter for adversary', () => {
    const nodeType = DiamondNodeEnum.adversary;
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
    const nodeType = DiamondNodeEnum.infrastructure;
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

describe('get the filters from Malware, containing a diamond ', () => {
  const entityType = DiamondEntityEnum.malware;

  it('should list filter for adversary', () => {
    const nodeType = DiamondNodeEnum.adversary;
    const expectedFilters = {
      mode: 'and',
      filters: [
        {
          key: 'entity_type',
          operator: 'eq',
          values: [
            'Intrusion-Set',
            'Threat-Actor-Group',
            'Threat-Actor-Individual',
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
                'authored-by',
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
    const nodeType = DiamondNodeEnum.infrastructure;
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
                'exfiltrates-to',
                'beacons-to',
                'communicates-to',
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
