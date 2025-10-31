import { describe, expect, it } from 'vitest';
import { convertWidgetsIds } from '../../../src/modules/workspace/workspace-utils';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { INSTANCE_REGARDING_OF, TYPE_FILTER } from '../../../src/utils/filtering/filtering-constants';
import { emptyFilterGroup } from '../../../src/utils/filtering/filtering-utils';
import { internalFindByIds } from '../../../src/database/middleware-loader';
import type { BasicStoreObject } from '../../../src/types/store';

describe('Workspace utils', () => {
  it('should convert widget filters ids', async () => {
    // find internal ids associated to standard ids
    const reportStandardId = 'report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7';
    const malwareStandardId = 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c';
    const softwareStandardId = 'software--b0debdba-74e7-4463-ad2a-34334ee66d8d';
    const resolveOpts = { baseData: true, toMap: true, mapWithAllIds: true };
    const objects = await internalFindByIds(testContext, ADMIN_USER, [reportStandardId, malwareStandardId, softwareStandardId], resolveOpts);
    const objectsMap = objects as unknown as { [k: string]: BasicStoreObject };
    console.log('objectsMap[reportStandardId]', objectsMap[reportStandardId]);
    console.log('map', objectsMap);
    const reportInternalId = objectsMap[reportStandardId].internal_id;
    const malwareInternalId = objectsMap[malwareStandardId].internal_id;
    const softwareInternalId = objectsMap[softwareStandardId].internal_id;

    // construct the filters (with standard ids) to test
    const filters1 = {
      mode: 'and',
      filters: [
        { key: TYPE_FILTER, values: ['Report', 'Malware'], operator: 'not_eq' },
        { key: INSTANCE_REGARDING_OF,
          values: [
            { key: 'relationship_type', values: ['related-to', 'located-at'] },
            { key: 'id', values: [reportInternalId, malwareInternalId] },
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
    const filters2 = emptyFilterGroup;
    const input = [
      {
        type: 'list',
        perspective: 'entities',
        parameters: {},
        dataSelection: [{
          number: 10,
          attribute: 'entity_type',
          date_attribute: 'created_at',
          filters: filters1,
          dynamicFrom: filters2,
          dynamicTo: undefined,
        }],
      }
    ];

    // construct the expected result (filters with internal ids)

    // check the result
    const result = await convertWidgetsIds(testContext, ADMIN_USER, input, 'internal');
    expect(result).toEqual('test');
  });
});
