import * as R from 'ramda';
import { describe, expect, it, vi } from 'vitest';
import type { Request, Response } from 'express';
import { appLogLevelMaxArraySize, appLogLevelMaxStringSize, logApp, prepareLogMetadata } from '../../../src/config/conf';
import { requestLogContextMiddleware } from '../../../src/config/log-context';
import { FunctionalError } from '../../../src/config/errors';

// region objects definition
const CLASSIC_OBJECT = {
  category: 'APP',
  errors: [
    {
      attributes: {
        errors: [
          {
            index: 'opencti_stix_domain_objects-000001',
            index_uuid: 'ntQ2slJaRmWphjOmcls3lA',
            reason: 'reason',
            shard: '0',
            type: 'version_conflict_engine_exception',
          },
        ],
        genre: 'TECHNICAL',
        http_status: 500,
      },
      message: 'Bulk indexing fail',
      name: 'DATABASE_ERROR',
      stack: 'GraphQLError: Bulk indexing fail',
    },
  ],
  id: '3f001108-c42c-4131-b3a3-583a98043c15',
  level: 'error',
  manager: 'RETENTION_MANAGER',
  message: 'Bulk indexing fail',
  source: 'backend',
  timestamp: '2025-01-09T20:57:05.422Z',
  version: '6.4.6',
};
const CATEGORY_TO_LIMIT = [
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
  'Item 56',
];
const TOO_COMPLEX_OBJECT = {
  category: 'APP',
  cause: FunctionalError('my error', { category_to_limit: CATEGORY_TO_LIMIT }),
  errors: [
    {
      category_to_limit: CATEGORY_TO_LIMIT,
    },
    {
      category_to_limit: ['2', '1', '3'],
    },
  ],
  id: '3f001108-c42c-4131-b3a3-583a98043c15',
  level: 'error',
  source: R.range(1, 6000).map(() => 'A').join(''),
  timestamp: '2025-01-09T20:57:05.422Z',
};
const WITH_ERROR_OBJECT = {
  level: 'error',
  cause: FunctionalError('my error', { cause: new Error('embedded error') }),
  timestamp: '2025-01-09T20:57:05.422Z',
};
// endregion

describe('Logger test suite', () => {
  it('Log object is correctly untouched', () => {
    const cleanObject = prepareLogMetadata(CLASSIC_OBJECT);
    const classicCompare = R.dissoc('version', CLASSIC_OBJECT);
    const cleanCompare = R.dissoc('version', cleanObject);
    expect(JSON.stringify(cleanCompare)).toEqual(JSON.stringify(classicCompare));
  });

  it('Log object with error correctly formatted', () => {
    const cleanObject = prepareLogMetadata(WITH_ERROR_OBJECT);
    expect(cleanObject.cause.message).toBe('my error');
    expect(cleanObject.cause.attributes.cause.message).toBe('embedded error');
  });

  it('Log error given directly as metadata keeps its fields', () => {
    const cleanObject = prepareLogMetadata(new Error('direct error'));
    expect(cleanObject.name).toBe('Error');
    expect(cleanObject.message).toBe('direct error');
    expect(cleanObject.stack).toContain('direct error');
  });

  it('Log error given directly as metadata keeps its fields with a request context', () => {
    const cleanObject = prepareLogMetadata(new Error('direct error'), {}, { user_agent: 'pycti/6.9.0' });
    expect(cleanObject.message).toBe('direct error');
    expect(cleanObject.stack).toContain('direct error');
    expect(cleanObject.user_agent).toBe('pycti/6.9.0');
  });

  it('Log error given directly to logApp keeps its fields, inside and outside a request', () => {
    // The console transport writes to console._stdout
    const stdout = (console as unknown as { _stdout: { write: (chunk: string) => boolean } })._stdout;
    const write = vi.spyOn(stdout, 'write').mockImplementation(() => true);
    try {
      logApp.error('DIRECT_ERROR_OUTSIDE', new Error('outside error'));
      requestLogContextMiddleware({ header: () => 'pycti/6.9.0' } as unknown as Request, {} as Response, () => {
        logApp.error('DIRECT_ERROR_INSIDE', new Error('inside error'));
      });
      const findLine = (marker: string) => {
        const line = write.mock.calls.map(([chunk]) => String(chunk)).find((chunk) => chunk.includes(marker));
        return JSON.parse(line ?? '{}');
      };
      const outside = findLine('DIRECT_ERROR_OUTSIDE');
      expect(outside.name).toBe('Error');
      expect(outside.stack).toContain('outside error');
      expect(outside.user_agent).toBeUndefined();
      const inside = findLine('DIRECT_ERROR_INSIDE');
      expect(inside.name).toBe('Error');
      expect(inside.stack).toContain('inside error');
      expect(inside.user_agent).toBe('pycti/6.9.0');
    } finally {
      write.mockRestore();
    }
  });

  it('Log explicit metadata wins over the request context', () => {
    const cleanObject = prepareLogMetadata({ user_agent: 'explicit' }, {}, { user_agent: 'from-request' });
    expect(cleanObject.user_agent).toBe('explicit');
  });

  it('Log request context is limited', () => {
    const longUserAgent = R.range(0, appLogLevelMaxStringSize + 100).map(() => 'A').join('');
    const cleanObject = prepareLogMetadata({}, {}, { user_agent: longUserAgent });
    expect(cleanObject.user_agent.length).toBe(appLogLevelMaxStringSize);
  });

  it('Log object is correctly limited', () => {
    let initialSize = CATEGORY_TO_LIMIT.length;
    const start = new Date().getTime();
    const cleanObject = prepareLogMetadata(TOO_COMPLEX_OBJECT);
    const parsingTimeMs = new Date().getTime() - start;
    expect(parsingTimeMs).to.be.lt(8);
    let cleanedSize = cleanObject.cause.attributes.category_to_limit.length;
    expect(initialSize).not.toEqual(cleanedSize);
    expect(initialSize).to.be.gt(appLogLevelMaxArraySize);
    expect(cleanedSize).to.be.eq(appLogLevelMaxArraySize);
    // check more inside look
    initialSize = TOO_COMPLEX_OBJECT.errors[0].category_to_limit.length;
    cleanedSize = cleanObject.errors[0].category_to_limit.length;
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
