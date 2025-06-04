import { describe, expect, it, vi } from 'vitest';
import { csvFeedGetCsvMapper } from '../../../src/modules/ingestion/ingestion-csv-domain';
import type { BasicStoreEntityIngestionCsv } from '../../../src/modules/ingestion/ingestion-types';
import type { AuthContext } from '../../../src/types/user';
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
  it('should return parsed CSV mapper when the type is inline', () => {
    const ingestionCsv: BasicStoreEntityIngestionCsv = {
      id: 'test-id-inline',
      csv_mapper_type: IngestionCsvMapperType.Inline,
      csv_mapper: '{"openCTI_version":"6.6.6","type":"csvMapper"}',
      csv_mapper_id: 'some-id', // this won't be used
    } as unknown as BasicStoreEntityIngestionCsv;

    const context: AuthContext = {} as unknown as AuthContext;

    const result = csvFeedGetCsvMapper(context, ingestionCsv);

    expect(result.id).toBeTruthy();
    expect(result.type).toEqual('csvMapper');
    expect(result.openCTI_version).toEqual('6.6.6');
  });
});
