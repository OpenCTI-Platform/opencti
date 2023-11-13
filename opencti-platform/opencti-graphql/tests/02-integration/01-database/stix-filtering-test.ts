import { describe, expect, it } from 'vitest';

import { ADMIN_USER, buildStandardUser, testContext } from '../../utils/testQuery';
import { isStixMatchFilterGroup_MockableForUnitTests } from '../../../src/utils/stix-filtering/stix-filtering';
import type { FilterGroup } from '../../../src/utils/stix-filtering/filter-group';

import stixReports from '../../data/stream-events/stream-event-stix2-reports.json';
import stixIndicators from '../../data/stream-events/stream-event-stix2-indicators.json';

const stixReport = stixReports[0]; //  confidence 3, revoked=false, labels=report, TLP:TEST
const stixIndicator = stixIndicators[0]; // confidence 75, revoked=true, no label

const TLP_CLEAR_ID = 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9';
const WHITE_TLP = { standard_id: TLP_CLEAR_ID, internal_id: '' };

const MOCK_RESOLUTION_MAP: Map<string, string> = new Map();
MOCK_RESOLUTION_MAP.set('id-for-label-indicator', 'indicator');
MOCK_RESOLUTION_MAP.set('id-for-marking-tlp:green', 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9');

describe('Stix Filtering', () => {
  it('matches stix objects with basic filter groups', async () => {
    let filterGroup: FilterGroup = {
      mode: 'and',
      filters: [{
        key: ['entity_type'],
        mode: 'or',
        operator: 'eq',
        values: ['Report']
      }],
      filterGroups: [],
    };
    expect(await isStixMatchFilterGroup_MockableForUnitTests(testContext, ADMIN_USER, stixReport, filterGroup, MOCK_RESOLUTION_MAP)).toEqual(true);
    expect(await isStixMatchFilterGroup_MockableForUnitTests(testContext, ADMIN_USER, stixIndicator, filterGroup, MOCK_RESOLUTION_MAP)).toEqual(false);

    filterGroup = {
      mode: 'and',
      filters: [{
        key: ['entity_type'],
        mode: 'or',
        operator: 'eq',
        values: ['Report', 'Indicator']
      }],
      filterGroups: [],
    };

    expect(await isStixMatchFilterGroup_MockableForUnitTests(testContext, ADMIN_USER, stixReport, filterGroup, MOCK_RESOLUTION_MAP)).toEqual(true);
    expect(await isStixMatchFilterGroup_MockableForUnitTests(testContext, ADMIN_USER, stixIndicator, filterGroup, MOCK_RESOLUTION_MAP)).toEqual(true);
  });

  it('prevent access to stix object according to marking', async () => {
    const filterGroup: FilterGroup = {
      mode: 'and',
      filters: [{
        key: ['entity_type'],
        mode: 'or',
        operator: 'eq',
        values: ['Report']
      }],
      filterGroups: [],
    };

    const WHITE_USER = buildStandardUser([WHITE_TLP]);
    expect(await isStixMatchFilterGroup_MockableForUnitTests(testContext, WHITE_USER, stixReport, filterGroup, MOCK_RESOLUTION_MAP)).toEqual(false);
  });

  // TODO: add test with resolution of labels/indicators in filterGroup

  it('matches stix objects with complex filter groups', async () => {
    const filterGroup: FilterGroup = {
      mode: 'and',
      filters: [],
      filterGroups: [
        {
          mode: 'and',
          filters: [{
            key: ['entity_type'],
            mode: 'or',
            operator: 'eq',
            values: ['Report', 'Indicator']
          }, {
            key: ['confidence'],
            mode: 'and',
            operator: 'gt',
            values: ['25']
          }],
          filterGroups: [],
        },
        {
          mode: 'and',
          filters: [{
            key: ['revoked'],
            mode: 'or',
            operator: 'eq',
            values: ['true']
          }, {
            key: ['objectLabel'],
            mode: 'or',
            operator: 'eq',
            values: ['id-for-label-indicator']
          }, {
            key: ['objectMarking'],
            mode: 'or',
            operator: 'eq',
            values: ['id-for-marking-tlp:green']
          }],
          filterGroups: [],
        },
      ],
    };
    expect(await isStixMatchFilterGroup_MockableForUnitTests(testContext, ADMIN_USER, stixReport, filterGroup, MOCK_RESOLUTION_MAP)).toEqual(false);
    expect(await isStixMatchFilterGroup_MockableForUnitTests(testContext, ADMIN_USER, stixIndicator, filterGroup, MOCK_RESOLUTION_MAP)).toEqual(true);
  });

  it('throws error when filter group is invalid', async () => {
    const multipleKeys: FilterGroup = {
      mode: 'and',
      filters: [
        { key: ['entity_type'], mode: 'or', operator: 'eq', values: ['Report'] }, // valid
        { key: ['createdBy', 'objectAssignee'], mode: 'or', operator: 'eq', values: ['id1'] }, // invalid
      ],
      filterGroups: [],
    };
    await expect(() => isStixMatchFilterGroup_MockableForUnitTests(testContext, ADMIN_USER, stixReport, multipleKeys, MOCK_RESOLUTION_MAP)).rejects.toThrowError('Stix filtering can only be executed on a unique filter key');

    const multipleKeysNested: FilterGroup = {
      mode: 'and',
      filters: [],
      filterGroups: [{
        mode: 'and',
        filters: [
          { key: ['entity_type'], mode: 'or', operator: 'eq', values: ['Report'] }, // valid
          { key: ['createdBy', 'objectAssignee'], mode: 'or', operator: 'eq', values: ['id1'] }, // invalid
        ],
        filterGroups: [],
      }],
    };

    await expect(() => isStixMatchFilterGroup_MockableForUnitTests(testContext, ADMIN_USER, stixReport, multipleKeysNested, MOCK_RESOLUTION_MAP)).rejects.toThrowError('Stix filtering can only be executed on a unique filter key');

    const unhandledKeys: FilterGroup = {
      mode: 'and',
      filters: [
        { key: ['entity_type'], mode: 'or', operator: 'eq', values: ['Report'] }, // valid
        { key: ['bad_key'], mode: 'or', operator: 'eq', values: ['id1'] }, // invalid
      ],
      filterGroups: [],
    };

    await expect(() => isStixMatchFilterGroup_MockableForUnitTests(testContext, ADMIN_USER, stixReport, unhandledKeys, MOCK_RESOLUTION_MAP)).rejects.toThrowError('Stix filtering is not compatible with the provided filter key');

    const unhandledKeysNested: FilterGroup = {
      mode: 'and',
      filters: [],
      filterGroups: [{
        mode: 'and',
        filters: [
          { key: ['entity_type'], mode: 'or', operator: 'eq', values: ['Report'] }, // valid
          { key: ['bad_key'], mode: 'or', operator: 'eq', values: ['id1'] }, // invalid
        ],
        filterGroups: [],
      }],
    };

    await expect(() => isStixMatchFilterGroup_MockableForUnitTests(testContext, ADMIN_USER, stixReport, unhandledKeysNested, MOCK_RESOLUTION_MAP)).rejects.toThrowError('Stix filtering is not compatible with the provided filter key');
  });
});
