import { describe, it, expect } from 'vitest';
import { checkPlaybookFiltersAndBuildConfigWithCorrectFilters } from '../../../src/modules/playbook/playbook-utils';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { PLAYBOOK_MATCHING_COMPONENT } from '../../../src/modules/playbook/playbook-components';
import {
  CREATOR_FILTER,
  LABEL_FILTER,
  ME_FILTER_VALUE,
  REPRESENTATIVE_FILTER
} from '../../../src/utils/filtering/filtering-constants';

describe('Playbook utils: checkPlaybookFiltersAndBuildConfigWithCorrectFilters', () => {
  it('Stix playbook components: should check playbook filters and build config with correct filters', async () => {
    const userId = 'user1-id';
    const filters = {
      mode: 'and',
      filters: [
        { key: [CREATOR_FILTER], values: [ME_FILTER_VALUE] },
        { key: [REPRESENTATIVE_FILTER], values: [ME_FILTER_VALUE], operator: 'includes' },
      ],
      filterGroups: [{
        mode: 'or',
        filters: [
          { key: [CREATOR_FILTER], values: [ME_FILTER_VALUE], operator: 'not_eq' },
          { key: [LABEL_FILTER], values: ['label1'] },
        ],
        filterGroups: [],
      }]
    };
    const expectedFilters = {
      mode: 'and',
      filters: [
        { key: [REPRESENTATIVE_FILTER], values: [ME_FILTER_VALUE], operator: 'includes' },
      ],
      filterGroups: [{
        mode: 'or',
        filters: [
          { key: [LABEL_FILTER], values: ['label1'] },
        ],
        filterGroups: [],
      }],
    };
    const input = {
      component_id: PLAYBOOK_MATCHING_COMPONENT.id,
      name: PLAYBOOK_MATCHING_COMPONENT.name,
      configuration: JSON.stringify({
        filters: JSON.stringify(filters),
      }),
      position: { x: 1, y: 1 },
    };
    const result = await checkPlaybookFiltersAndBuildConfigWithCorrectFilters(testContext, ADMIN_USER, input, userId);
    expect(result).toEqual(JSON.stringify({ filters: JSON.stringify(expectedFilters) }));
  });

  it('Stix playbook components: should check playbook filters and return an error if filters are incorrect', async () => {
    const userId = 'user1-id';
    const filters = {
      mode: 'or',
      filters: [
        { key: ['description'], values: ['test'] }, // key not compatible with stix filtering
        { key: [REPRESENTATIVE_FILTER], values: ['test'] },
      ],
      filterGroups: [],
    };
    const input = {
      component_id: PLAYBOOK_MATCHING_COMPONENT.id,
      name: PLAYBOOK_MATCHING_COMPONENT.name,
      configuration: JSON.stringify({
        filters: JSON.stringify(filters),
      }),
      position: { x: 1, y: 1 },
    };
    await expect(async () => await checkPlaybookFiltersAndBuildConfigWithCorrectFilters(testContext, ADMIN_USER, input, userId))
      .rejects.toThrowError('Stix filtering is not compatible with the provided filter key');
  });
  });