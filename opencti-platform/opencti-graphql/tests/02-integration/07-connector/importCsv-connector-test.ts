import { describe, it, expect } from 'vitest';
import { fileToReadStream, uploadToStorage } from '../../../src/database/file-storage-helper';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { IMPORT_STORAGE_PATH } from '../../../src/modules/internal/document/document-domain';
import { consumeQueueCallback } from '../../../src/connector/importCsv/importCsv-connector';
import { csvMapperMockSimpleCities } from '../../data/importCsv-connector/csv-mapper-cities';
import { createWork, findById as findWorkById } from '../../../src/domain/work';
import { IMPORT_CSV_CONNECTOR } from '../../../src/connector/importCsv/importCsv';

describe('Verify internal importCsv connector', () => {
  let work: any;

  it('should upload csv file and create work that is use for this test', async () => {
    const file = fileToReadStream('./tests/data/importCsv-connector', 'csv-file-cities-for-importCsv-connector.csv', 'csv-file-cities-for-importCsv-connector.csv', 'text/csv');
    const uploadedFile = await uploadToStorage(testContext, ADMIN_USER, `${IMPORT_STORAGE_PATH}/global`, file, {});
    expect(uploadedFile).toBeDefined();
    expect(uploadedFile.upload.id).toBe('import/global/csv-file-cities-for-importcsv-connector.csv');

    work = await createWork(testContext, ADMIN_USER, IMPORT_CSV_CONNECTOR, '[File] Import csv for test', 'sourceTest');
  });

  it('should convert csv lines to bundle when line count < bulk_creation_size', async () => {
    const messageContent = {
      internal: {
        work_id: work.id,
        applicant_id: ADMIN_USER.id
      },
      event: {
        file_id: 'import/global/csv-file-cities-for-importcsv-connector.csv',
        file_mime: 'text/csv',
        file_fetch: '/storage/get/import/global/csv-file-cities-for-importcsv-connector.csv',
      },
      configuration: JSON.stringify(csvMapperMockSimpleCities),
    };

    const message: string = JSON.stringify(messageContent);
    await consumeQueueCallback(testContext, message);
    // there is no worker so cannot do many expect.
    // But at least it should not raise exceptions.

    const workUpdated: any = await findWorkById(testContext, ADMIN_USER, work.id);
    expect(workUpdated).toBeDefined();
    expect(workUpdated.errors.length).toBe(0);
  });
});
