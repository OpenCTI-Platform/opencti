import { describe, expect, it, vi } from 'vitest';
import { csvFeedGetCsvMapper } from '../../../src/modules/ingestion/ingestion-csv-domain';
import type { BasicStoreEntityIngestionCsv } from '../../../src/modules/ingestion/ingestion-types';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import { IngestionCsvMapperType } from '../../../src/generated/graphql';

// Mock the storeLoadById function
const mockStoreLoadById = vi.fn();

vi.mock('../../database/middleware-loader', async () => { // Adjust the path accordingly
  const originalModule = (await vi.importActual('../../database/middleware-loader')) as any; // Adjust the path to actual module
  return {
    ...originalModule,
    storeLoadById: mockStoreLoadById,
  };
});

describe('csvFeedGetCsvMapper', () => {
  it('should return parsed CSV mapper when the type is inline', async () => {
    const ingestionCsv: BasicStoreEntityIngestionCsv = {
      id: 'test-id-inline',
      csv_mapper_type: IngestionCsvMapperType.Inline,
      csv_mapper: '{"id":"1","openCTI_version":"6.6.6","type":"csvMapper", "name": "Test", "has_header": true, "separator": ",", "skipLineChar": "", "representations": [] }',
      csv_mapper_id: 'some-id', // this won't be used
    } as unknown as BasicStoreEntityIngestionCsv;

    const context: AuthContext = { user: {} } as unknown as AuthContext;
    const userContext: AuthUser = {} as unknown as AuthUser;

    const result = await csvFeedGetCsvMapper(context, userContext, ingestionCsv);

    expect(result).toEqual({
      id: '1',
      type: 'csvMapper',
      openCTI_version: '6.6.6',
      has_header: true,
      name: 'Test',
      representations: [],
      separator: ',',
      skipLineChar: ''
    });
  });
});
