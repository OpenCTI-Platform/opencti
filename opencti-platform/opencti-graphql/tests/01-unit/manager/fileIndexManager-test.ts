import { describe, it, vi, expect, afterEach } from 'vitest';
import { indexImportedFiles } from '../../../src/manager/fileIndexManager';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import type { BasicStoreEntityDocument } from '../../../src/modules/internal/document/document-types';
import type { BasicStoreEntityManagerConfiguration } from '../../../src/modules/managerConfiguration/managerConfiguration-types';
import { logApp } from '../../../src/config/conf';
import * as fileSearch from '../../../src/database/file-search';

const docList: BasicStoreEntityDocument[] = [];
const getMockDocument = (docId: string) => {
  const doc: Partial<BasicStoreEntityDocument> = {
    id: docId,
    metaData: {
      entity_id: 'mocked-unit-test-file',
      mimetype: ''
    }
  };
  return doc as BasicStoreEntityDocument;
};
docList.push(getMockDocument('doc1'));
docList.push(getMockDocument('doc2'));
docList.push(getMockDocument('doc3'));

describe.concurrent('Testing exception management in FileIndexManager', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  vi.mock('../../../src/modules/internal/document/document-domain', () => {
    return {
      allFilesForPaths: vi.fn(() => docList),
    };
  });

  // GIVEN one document in the list that throw an error.
  vi.mock('../../../src/database/file-storage', () => {
    return {
      getFileContent: vi.fn().mockImplementation((id) => {
        if (id === 'doc2') {
          throw new Error('thrown error');
        }
      }),
    };
  });

  vi.mock('../../../src/modules/managerConfiguration/managerConfiguration-domain', () => {
    return {
      getManagerConfigurationFromCache: vi.fn().mockImplementation(() => {
        const managerMock : Partial<BasicStoreEntityManagerConfiguration> = {
          manager_running: true,
        };
        return managerMock;
      }),
    };
  });

  it('should not block indexing when an exception is raised for one file.', async () => {
    const logAppErrorSpy = vi.spyOn(logApp, 'error');
    const elIndexFilesSpy = vi.spyOn(fileSearch, 'elIndexFiles');

    const mockAuthUser: Partial<AuthUser> = {
      id: 'test-user',
      name: 'test-user',
      user_email: 'test-user',
    };

    const mockAuthContext: AuthContext = {
      otp_mandatory: false,
      source: 'file-manager-unit-test',
      tracing: {},
      user: mockAuthUser as AuthUser,
    };

    // WHEN the fileIndexManager main process is call
    await indexImportedFiles(mockAuthContext, Date.now().toString());

    // THEN error is logged and process continue.
    expect(true, 'No exception should be raised outside of indexImportedFiles to not block indexing.').toBeTruthy();
    expect(logAppErrorSpy, 'One logApp.error should have been called.').toHaveBeenCalledTimes(1);
    expect(elIndexFilesSpy, 'elIndexFiles should be called despite one exception raised in loadFilesToIndex').toHaveBeenCalledTimes(1);
  });
});
