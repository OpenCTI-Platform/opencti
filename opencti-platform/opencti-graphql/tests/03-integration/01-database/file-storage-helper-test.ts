import { describe, expect, it } from 'vitest';
import { fileToReadStream, uploadToStorage } from '../../../src/database/file-storage';
import type { AuthContext } from '../../../src/types/user';
import { ADMIN_USER } from '../../utils/testQuery';
import { MARKING_TLP_CLEAR } from '../../../src/schema/identifier';
import { findById as findDocumentById, SUPPORT_STORAGE_PATH } from '../../../src/modules/internal/document/document-domain';

const adminContext: AuthContext = {
  user: ADMIN_USER,
  tracing: undefined,
  source: 'file-storage-helper-test',
  otp_mandatory: false,
  user_inside_platform_organization: false,
};

describe('File storage upload with marking', () => {
  it('should file upload succeed to S3 and data in elastic have marking stored.', async () => {
    const file = fileToReadStream('./tests/data/', 'file-storage-helper-test.txt', 'file-storage-test.txt', 'text/plain');
    const uploadedFileWithMarking = await uploadToStorage(adminContext, ADMIN_USER, SUPPORT_STORAGE_PATH, file, { file_markings: [MARKING_TLP_CLEAR] });
    expect(uploadedFileWithMarking.upload.id).toBeDefined();
    // and expect no exception.

    const document = await findDocumentById(adminContext, ADMIN_USER, uploadedFileWithMarking.upload.id);
    expect(document.metaData.file_markings).toBeDefined();
    expect(document.metaData.file_markings?.length, 'One marking MARKING_TLP_CLEAR is expected on this document.').toBe(1);
    if (document.metaData.file_markings) {
      expect(document.metaData.file_markings[0]).toBe(MARKING_TLP_CLEAR);
    }
  });
});
