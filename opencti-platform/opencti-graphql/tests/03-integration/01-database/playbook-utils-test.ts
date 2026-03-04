import { describe, expect, it } from 'vitest';
import { checkPlaybookFiltersAndBuildConfigWithCorrectFilters } from '../../../src/modules/playbook/playbook-utils';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { PLAYBOOK_INTERNAL_DATA_CRON, PLAYBOOK_MATCHING_COMPONENT } from '../../../src/modules/playbook/playbook-components';
import { CREATOR_FILTER, LABEL_FILTER, REPRESENTATIVE_FILTER } from '../../../src/utils/filtering/filtering-constants';

describe('Playbook utils: checkPlaybookFiltersAndBuildConfigWithCorrectFilters', () => {
  it('should check playbook filters and build config with correct filters for stix components', async () => {
    const userId = 'user1-id';
    const filters = {
      mode: 'and',
      filters: [
        { key: [REPRESENTATIVE_FILTER], values: ['test'], operator: 'includes' },
      ],
      filterGroups: [{
        mode: 'or',
        filters: [
          { key: [CREATOR_FILTER], values: ['user1_id'], operator: 'not_eq' },
          { key: [LABEL_FILTER], values: ['label1', 'label2'] },
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
    expect(result).toEqual(JSON.stringify({ filters: JSON.stringify(filters) }));
  });

  it('should check playbook filters and return an error if filters are incorrect for stix components', async () => {
    const userId = 'user1-id';
    const filters = {
      mode: 'or',
      filters: [
        { key: ['description'], values: ['test'] }, // key not compatible with stix filtering
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

  it('should check playbook filters and build config with correct filters for data cron component', async () => {
    const userId = 'user1-id';
    const filters = {
      mode: 'and',
      filters: [
        { key: ['name'], values: ['test'], operator: 'includes' },
        { key: [CREATOR_FILTER], values: ['@me'], operator: 'not_eq' }, // @me value to be replaced by user id
      ],
      filterGroups: [{
        mode: 'or',
        filters: [
          { key: [LABEL_FILTER], values: ['label1', 'label2'] },
        ],
        filterGroups: [],
      }],
    };
    const expectedFilters = {
      mode: 'and',
      filters: [
        { key: ['name'], values: ['test'], operator: 'includes' },
        { key: [CREATOR_FILTER], values: [userId], operator: 'not_eq' },
      ],
      filterGroups: [{
        mode: 'or',
        filters: [
          { key: [LABEL_FILTER], values: ['label1', 'label2'] },
        ],
        filterGroups: [],
      }],
    };
    const input = {
      component_id: PLAYBOOK_INTERNAL_DATA_CRON.id,
      name: PLAYBOOK_INTERNAL_DATA_CRON.name,
      configuration: JSON.stringify({
        filters: JSON.stringify(filters),
      }),
      position: { x: 1, y: 1 },
    };
    const result = await checkPlaybookFiltersAndBuildConfigWithCorrectFilters(testContext, ADMIN_USER, input, userId);
    expect(result).toEqual(JSON.stringify({ filters: JSON.stringify(expectedFilters) }));
  });

  it('should check playbook filters and return an error if filters are incorrect for data cron component', async () => {
    const userId = 'user1-id';
    const filters = {
      mode: 'or',
      filters: [
        { key: [REPRESENTATIVE_FILTER], values: ['test'] }, // key not compatible with dynamic filtering
      ],
      filterGroups: [],
    };
    const input = {
      component_id: PLAYBOOK_INTERNAL_DATA_CRON.id,
      name: PLAYBOOK_INTERNAL_DATA_CRON.name,
      configuration: JSON.stringify({
        filters: JSON.stringify(filters),
      }),
      position: { x: 1, y: 1 },
    };
    await expect(async () => await checkPlaybookFiltersAndBuildConfigWithCorrectFilters(testContext, ADMIN_USER, input, userId))
      .rejects.toThrowError('Incorrect filter keys not existing in any schema definition');
  });
});
