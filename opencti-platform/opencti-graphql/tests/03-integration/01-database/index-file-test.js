import { describe, expect, it } from 'vitest';
import * as R from 'ramda';
import { createReadStream } from 'node:fs';
import { elLoadById } from '../../../src/database/engine';
import { elIndexFiles, elSearchFiles } from '../../../src/database/file-search';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { getFileContent } from '../../../src/database/raw-file-storage';
import { INDEX_FILES } from '../../../src/database/utils';
import { resetFileIndexing } from '../../../src/domain/indexedFile';
import { uploadToStorage } from '../../../src/database/file-storage';
import { getManagerConfigurationFromCache, updateManagerConfigurationLastRun } from '../../../src/modules/managerConfiguration/managerConfiguration-domain';
import { SYSTEM_USER } from '../../../src/utils/access';

const indexFile = async (fileName, mimetype, documentId) => {
  const file = {
    createReadStream: () => createReadStream(`./tests/data/${fileName}`),
    filename: fileName,
    mimetype,
  };
  // upload file in minio
  const { upload: uploadedFile } = await uploadToStorage(testContext, ADMIN_USER, 'import/global', file, {});

  // get file content in base64
  const fileContent = await getFileContent(uploadedFile.id, 'base64');

  const fileToIndex = {
    internal_id: documentId,
    file_id: uploadedFile.id,
    file_data: fileContent,
    entity_id: '',
    name: fileName,
    uploaded_at: file.lastModified,
  };

  // index file content
  await elIndexFiles(testContext, ADMIN_USER, [fileToIndex]);

  // load file document
  const document = await elLoadById(testContext, ADMIN_USER, documentId, { indices: INDEX_FILES });

  return { document, uploadedFileId: uploadedFile.id };
};

const testFileIndexing = async (result, mimeType) => {
  // Assertions
  expect(result.document.attachment).not.toBeNull();
  expect(result.document.attachment.content).not.toBeNull();
  expect(result.document.attachment.content_type.includes(mimeType)).toBeTruthy();
  expect(result.document.file_id).toEqual(result.uploadedFileId);
};

const testFilesSearching = async (search, expectedFiles) => {
  const data = await elSearchFiles(testContext, ADMIN_USER, { search });
  expect(data).not.toBeNull();
  expect(data.edges.length).toEqual(expectedFiles.length);
  const resultFiles = data.edges.map((edge) => R.dissoc('sort', edge.node));
  expect(resultFiles).toEqual(expectedFiles);
};

describe('Indexing file test', () => {
  let document1;
  let document2;
  let document4;
  it('Should index small pdf file', async () => {
    const mimeType = 'application/pdf';
    const result = await indexFile('test-report-to-index.pdf', mimeType, 'TEST_FILE_1');
    await testFileIndexing(result, mimeType);
    document1 = result.document;
  });
  it('Should index large pdf file', async () => {
    const mimeType = 'application/pdf';
    const result = await indexFile('test-large-report-to-index.pdf', mimeType, 'TEST_FILE_2');
    await testFileIndexing(result, mimeType);
    document2 = result.document;
  });
  it('Should index txt file', async () => {
    const mimeType = 'text/plain';
    const result = await indexFile('test-file-to-index.txt', mimeType, 'TEST_FILE_3');
    await testFileIndexing(result, mimeType);
  });
  it('Should index csv file', async () => {
    const mimeType = 'text/plain';
    const result = await indexFile('test-file-to-index.csv', mimeType, 'TEST_FILE_4');
    await testFileIndexing(result, mimeType);
    document4 = result.document;
  });
  it('Should index xls file', async () => {
    const mimeType = 'application/vnd.ms-excel';
    const result = await indexFile('test-file-to-index.xls', mimeType, 'TEST_FILE_5');
    await testFileIndexing(result, mimeType);
  });
  it('Should index xlsx file', async () => {
    const mimeType = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
    const result = await indexFile('test-file-to-index.xlsx', mimeType, 'TEST_FILE_6');
    await testFileIndexing(result, mimeType);
  });
  it('Should index html file', async () => {
    const mimeType = 'text/html';
    const result = await indexFile('test-file-to-index.html', mimeType, 'TEST_FILE_7');
    await testFileIndexing(result, mimeType);
  });
  it('Should find document by search query', async () => {
    const expectedFile1 = {
      _index: 'test_files-000001',
      id: 'TEST_FILE_1',
      internal_id: 'TEST_FILE_1',
      name: 'test-report-to-index.pdf',
      indexed_at: document1.indexed_at,
      uploaded_at: document1.uploaded_at,
      entity_id: undefined,
      file_id: 'import/global/test-report-to-index.pdf',
      searchOccurrences: 11,
    };
    await testFilesSearching('elastic', [expectedFile1]);

    const expectedFile4 = {
      _index: 'test_files-000001',
      id: 'TEST_FILE_4',
      internal_id: 'TEST_FILE_4',
      name: 'test-file-to-index.csv',
      indexed_at: document4.indexed_at,
      uploaded_at: document4.uploaded_at,
      entity_id: undefined,
      file_id: 'import/global/test-file-to-index.csv',
      searchOccurrences: 3,
    };
    const expectedFile2 = {
      _index: 'test_files-000001',
      id: 'TEST_FILE_2',
      internal_id: 'TEST_FILE_2',
      name: 'test-large-report-to-index.pdf',
      indexed_at: document2.indexed_at,
      uploaded_at: document2.uploaded_at,
      entity_id: undefined,
      file_id: 'import/global/test-large-report-to-index.pdf',
      searchOccurrences: 1,
    };
    await testFilesSearching('control', [expectedFile4, expectedFile2]);
  });
});

describe('Indexing file configuration', () => {
  it('Should reset file indexing', async () => {
    const managerConfiguration = await getManagerConfigurationFromCache(testContext, ADMIN_USER, 'FILE_INDEX_MANAGER');
    // set last run start and end date (otherwise reset won't change anything)
    await updateManagerConfigurationLastRun(testContext, SYSTEM_USER, managerConfiguration.id, { last_run_start_date: new Date(), last_run_end_date: new Date() });
    const reset = await resetFileIndexing(testContext, ADMIN_USER);
    expect(reset).toBeTruthy();
    const data = await elSearchFiles(testContext, ADMIN_USER, { search: 'elastic' });
    expect(data).not.toBeNull();
    expect(data.edges.length).toEqual(0);
  });
});
