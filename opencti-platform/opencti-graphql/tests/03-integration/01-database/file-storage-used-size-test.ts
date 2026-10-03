import fs from 'node:fs';
import { describe, expect, it } from 'vitest';
import { deleteFile, fileToReadStream, uploadToStorage } from '../../../src/database/file-storage';
import type { AuthContext } from '../../../src/types/user';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { getIndexedFilesUsedSize, SUPPORT_STORAGE_PATH } from '../../../src/modules/internal/document/document-domain';
import { addDraftWorkspace, deleteDraftWorkspace } from '../../../src/modules/draftWorkspace/draftWorkspace-domain';

const TEST_FILE_DIRECTORY = './tests/data/';
const TEST_FILE_NAME = 'file-storage-helper-test.txt';
const TEST_FILE_SIZE = fs.statSync(`${TEST_FILE_DIRECTORY}${TEST_FILE_NAME}`).size;

// Other tests leave files behind, so every assertion is on the change around one upload.
describe('Indexed files used size', () => {
  it('should grow by the uploaded file size and shrink back once it is deleted', async () => {
    const before = await getIndexedFilesUsedSize(testContext);

    const file = fileToReadStream(TEST_FILE_DIRECTORY, TEST_FILE_NAME, 'file-storage-used-size-test.txt', 'text/plain');
    const { upload } = await uploadToStorage(testContext, ADMIN_USER, SUPPORT_STORAGE_PATH, file, {});
    expect(upload.size).toBe(TEST_FILE_SIZE);
    expect(await getIndexedFilesUsedSize(testContext)).toBe(before + TEST_FILE_SIZE);

    await deleteFile(testContext, ADMIN_USER, upload.id);
    expect(await getIndexedFilesUsedSize(testContext)).toBe(before);
  });

  it('should count draft files, and stop counting them once the draft is deleted', async () => {
    const before = await getIndexedFilesUsedSize(testContext);

    const draft = await addDraftWorkspace(testContext, ADMIN_USER, { name: 'Indexed files used size draft' });
    const draftContext: AuthContext = { ...testContext, draft_context: draft.id };
    const file = fileToReadStream(TEST_FILE_DIRECTORY, TEST_FILE_NAME, 'file-storage-used-size-draft-test.txt', 'text/plain');
    await uploadToStorage(draftContext, ADMIN_USER, SUPPORT_STORAGE_PATH, file, {});
    // Counted from outside the draft too: the collection runs without any draft context.
    expect(await getIndexedFilesUsedSize(testContext)).toBe(before + TEST_FILE_SIZE);

    await deleteDraftWorkspace(testContext, ADMIN_USER, draft.id);
    expect(await getIndexedFilesUsedSize(testContext)).toBe(before);
  });
});
