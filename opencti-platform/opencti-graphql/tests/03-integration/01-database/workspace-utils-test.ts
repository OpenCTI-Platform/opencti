import { describe, expect, it } from 'vitest';
import { convertWidgetsIds } from '../../../src/modules/workspace/workspace-utils';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { INSTANCE_REGARDING_OF, TYPE_FILTER } from '../../../src/utils/filtering/filtering-constants';
import { emptyFilterGroup } from '../../../src/utils/filtering/filtering-utils';
import { internalFindByIds } from '../../../src/database/middleware-loader';
import { ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { ENTITY_SOFTWARE } from '../../../src/schema/stixCyberObservable';

describe('Workspace utils', () => {
  it('should convert widget filters ids', async () => {
    // find internal ids associated to standard ids for 3 entities that will be used in filters
    const reportId = 'report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7';
    const malwareId = 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c';
    const softwareId = 'software--b0debdba-74e7-4463-ad2a-34334ee66d8d';
    const resolveOpts = { baseData: true, mapWithAllIds: true };
    const objects = await internalFindByIds(testContext, ADMIN_USER, [reportId, malwareId, softwareId], resolveOpts);
    const reportInternalId = objects.find((o) => o.entity_type === ENTITY_TYPE_CONTAINER_REPORT)?.internal_id;
    const reportStandardId = objects.find((o) => o.entity_type === ENTITY_TYPE_CONTAINER_REPORT)?.standard_id;
    const malwareInternalId = objects.find((o) => o.entity_type === ENTITY_TYPE_MALWARE)?.internal_id;
    const malwareStandardId = objects.find((o) => o.entity_type === ENTITY_TYPE_MALWARE)?.standard_id;
    const softwareInternalId = objects.find((o) => o.entity_type === ENTITY_SOFTWARE)?.internal_id;
    const softwareStandardId = objects.find((o) => o.entity_type === ENTITY_SOFTWARE)?.standard_id;

    // construct the widget input (with standard ids in filters) to test
    const filters = {
      mode: 'and',
      filters: [
        { key: TYPE_FILTER, values: ['Report', 'Malware'], operator: 'not_eq' },
        { key: INSTANCE_REGARDING_OF,
          values: [
            { key: 'id', values: [reportInternalId, malwareInternalId] },
            { key: 'relationship_type', values: ['related-to', 'located-at'] },
          ] },
      ],
      filterGroups: [
        {
          mode: 'or',
          filters: [
            { key: 'object', values: [softwareInternalId, 'fakeId'], mode: 'and' },
            { key: 'objectMarking', values: ['markingId1'] },
          ],
          filterGroups: [],
        }
      ],
    };
    const input = [
      {
        type: 'list',
        perspective: 'entities',
        parameters: {},
        dataSelection: [{
          number: 10,
          attribute: 'entity_type',
          date_attribute: 'created_at',
          filters,
          dynamicFrom: emptyFilterGroup,
        }],
      }
    ];

    // construct the expected widget input result (filters with internal ids)
    const convertedFilters = {
      mode: 'and',
      filters: [
        { key: TYPE_FILTER, values: ['Report', 'Malware'], operator: 'not_eq' },
        { key: INSTANCE_REGARDING_OF,
          values: [
            { key: 'id', values: [reportStandardId, malwareStandardId] },
            { key: 'relationship_type', values: ['related-to', 'located-at'] },
          ] },
      ],
      filterGroups: [
        {
          mode: 'or',
          filters: [
            { key: 'object', values: [softwareStandardId, 'fakeId'], mode: 'and' },
            { key: 'objectMarking', values: ['markingId1'] },
          ],
          filterGroups: [],
        }
      ],
    };
    const convertedInput = [
      {
        type: 'list',
        perspective: 'entities',
        parameters: {},
        dataSelection: [{
          number: 10,
          attribute: 'entity_type',
          date_attribute: 'created_at',
          filters: convertedFilters,
          dynamicFrom: emptyFilterGroup,
        }],
      }
    ];
    // check the result
    await convertWidgetsIds(testContext, ADMIN_USER, input, 'internal');
    expect(input).toEqual(convertedInput);
  });
});
