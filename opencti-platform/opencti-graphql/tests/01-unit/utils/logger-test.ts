import * as R from 'ramda';
import { describe, expect, it } from 'vitest';
import { appLogLevelMaxArraySize, appLogLevelMaxStringSize, limitMetaErrorComplexity } from '../../../src/config/conf';

const CLASSIC_OBJECT = {
  category: 'APP',
  errors: [
    {
      attributes: {
        errors: [
          {
            index: 'opencti_stix_domain_objects-000001',
            index_uuid: 'ntQ2slJaRmWphjOmcls3lA',
            reason: '[b2349596-2fa3-4444-842d-effa8b34f267]: version conflict, required seqNo [51514085], primary term [64]. current document has seqNo [51514086] and primary term [64]',
            shard: '0',
            type: 'version_conflict_engine_exception'
          }
        ],
        genre: 'TECHNICAL',
        http_status: 500
      },
      message: 'Bulk indexing fail',
      name: 'DATABASE_ERROR',
      stack: 'GraphQLError: Bulk indexing fail\\n    at error (/opt/opencti/build/src/config/errors.js:7:10)\\n    at DatabaseError (/opt/opencti/build/src/config/errors.js:61:48)\\n    at /opt/opencti/build/src/database/engine.js:3425:13\\n    at processTicksAndRejections (node:internal/process/task_queues:95:5)\\n    at elRemoveRelationConnection (/opt/opencti/build/src/database/engine.js:3582:9)\\n    at elDeleteElements (/opt/opencti/build/src/database/engine.js:3773:3)\\n    at internalDeleteElementById (/opt/opencti/build/src/database/middleware.js:3253:7)\\n    at deleteElementById (/opt/opencti/build/src/database/middleware.js:3275:32)\\n    at deleteElement (/opt/opencti/build/src/manager/retentionManager.ts:37:5)\\n    at deleteFn (/opt/opencti/build/src/manager/retentionManager.ts:83:11)'
    }
  ],
  id: '3f001108-c42c-4131-b3a3-583a98043c15',
  level: 'error',
  manager: 'RETENTION_MANAGER',
  message: 'Bulk indexing fail',
  source: 'backend',
  timestamp: '2025-01-09T20:57:05.422Z',
  version: '6.4.6'
};

const TOO_COMPLEX_OBJECT = {
  category: 'APP',
  errors: [
    {
      attributes: {
        category_to_limit: [
          'Item 1',
          'Item 2',
          'Item 3',
          'Item 4',
          'Item 5',
          'Item 6',
          'Item 7',
          'Item 8',
          'Item 9',
          'Item 10',
          'Item 11',
          'Item 12',
          'Item 13',
          'Item 14',
          'Item 15',
          'Item 16',
          'Item 17',
          'Item 18',
          'Item 19',
          'Item 20',
          'Item 21',
          'Item 22',
          'Item 23',
          'Item 24',
          'Item 25',
          'Item 26',
          'Item 27',
          'Item 28',
          'Item 29',
          'Item 30',
          'Item 31',
          'Item 32',
          'Item 33',
          'Item 34',
          'Item 35',
          'Item 36',
          'Item 37',
          'Item 38',
          'Item 39',
          'Item 40',
          'Item 41',
          'Item 42',
          'Item 43',
          'Item 44',
          'Item 45',
          'Item 46',
          'Item 47',
          'Item 48',
          'Item 49',
          'Item 50',
          'Item 51',
          'Item 52',
          'Item 53',
          'Item 54',
          'Item 55',
          'Item 56'
        ]
      },
      message: 'Bulk indexing fail',
      name: 'DATABASE_ERROR',
      departments: [
        {
          departmentName: 'Research and Development',
          teams: [
            {
              teamName: 'AI Team',
              category_to_limit: [
                'Item 1',
                'Item 2',
                'Item 3',
                'Item 4',
                'Item 5',
                'Item 6',
                'Item 7',
                'Item 8',
                'Item 9',
                'Item 10',
                'Item 11',
                'Item 12',
                'Item 13',
                'Item 14',
                'Item 15',
                'Item 16',
                'Item 17',
                'Item 18',
                'Item 19',
                'Item 20',
                'Item 21',
                'Item 22',
                'Item 23',
                'Item 24',
                'Item 25',
                'Item 26',
                'Item 27',
                'Item 28',
                'Item 29',
                'Item 30',
                'Item 31',
                'Item 32',
                'Item 33',
                'Item 34',
                'Item 35',
                'Item 36',
                'Item 37',
                'Item 38',
                'Item 39',
                'Item 40',
                'Item 41',
                'Item 42',
                'Item 43',
                'Item 44',
                'Item 45',
                'Item 46',
                'Item 47',
                'Item 48',
                'Item 49',
                'Item 50',
                'Item 51',
                'Item 52',
                'Item 53',
                'Item 54',
                'Item 55',
                'Item 56'
              ]
            },
            {
              teamName: 'Robotics Team',
              category_to_limit: ['2', '1', '3'],
            }
          ]
        }
      ]
    }
  ],
  id: '3f001108-c42c-4131-b3a3-583a98043c15',
  level: 'error',
  source: R.range(1, 6000).map(() => 'A').join(''),
  timestamp: '2025-01-09T20:57:05.422Z'
};

describe('Logger test suite', () => {
  it('Log object is correctly untouched', () => {
    const cleanObject = limitMetaErrorComplexity(CLASSIC_OBJECT);
    expect(JSON.stringify(cleanObject)).toEqual(JSON.stringify(CLASSIC_OBJECT));
  });

  it('Log object is correctly limited', () => {
    let initialSize = TOO_COMPLEX_OBJECT.errors[0].attributes.category_to_limit.length;
    const start = new Date().getTime();
    const cleanObject = limitMetaErrorComplexity(TOO_COMPLEX_OBJECT);
    const parsingTimeMs = new Date().getTime() - start;
    expect(parsingTimeMs).to.be.lt(2);
    let cleanedSize = cleanObject.errors[0].attributes.category_to_limit.length;
    expect(initialSize).not.toEqual(cleanedSize);
    expect(initialSize).to.be.gt(appLogLevelMaxArraySize);
    expect(cleanedSize).to.be.eq(appLogLevelMaxArraySize);
    // check more inside look
    initialSize = TOO_COMPLEX_OBJECT.errors[0].departments[0].teams[0].category_to_limit.length;
    cleanedSize = cleanObject.errors[0].departments[0].teams[0].category_to_limit.length;
    expect(initialSize).not.toEqual(cleanedSize);
    expect(initialSize).to.be.gt(appLogLevelMaxArraySize);
    expect(cleanedSize).to.be.eq(appLogLevelMaxArraySize);
    initialSize = TOO_COMPLEX_OBJECT.source.length;
    cleanedSize = cleanObject.source.length;
    // Check max string
    expect(initialSize).not.toEqual(cleanedSize);
    expect(initialSize).to.be.gt(appLogLevelMaxStringSize);
    expect(cleanedSize).to.be.eq(appLogLevelMaxStringSize);
  });
});
