import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import type { LoadedFile } from '../../../src/database/file-storage';

const { mockConnectorsForImport, mockCreateWork, mockPushToConnector } = vi.hoisted(() => ({
  mockConnectorsForImport: vi.fn(),
  mockCreateWork: vi.fn(),
  mockPushToConnector: vi.fn(),
}));

vi.mock('../../../src/modules/connector/connector-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/modules/connector/connector-domain')>()),
  connectorsForImport: mockConnectorsForImport,
}));

vi.mock('../../../src/domain/work', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/domain/work')>()),
  createWork: mockCreateWork,
}));

vi.mock('../../../src/modules/connector/connector-rabbitmq', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/modules/connector/connector-rabbitmq')>()),
  pushToConnector: mockPushToConnector,
}));

import { uploadJobImport } from '../../../src/database/file-storage';

const context = {} as AuthContext;
const user = { id: 'user-1' } as AuthUser;
const file = {
  id: 'import/global/report.json',
  name: 'report.json',
  metaData: { mimetype: 'application/json', file_markings: [] },
} as unknown as LoadedFile;
const IMPORT_CONNECTORS = [
  { id: 'connector-1', internal_id: 'connector-1', name: 'Import connector 1', only_contextual: false },
  { id: 'connector-2', internal_id: 'connector-2', name: 'Import connector 2', only_contextual: false },
];

describe('uploadJobImport', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockConnectorsForImport.mockResolvedValue(IMPORT_CONNECTORS);
    mockCreateWork.mockImplementation(async (_context, _user, connector) => ({ id: `work-of-${connector.id}` }));
  });

  it('should ask every import connector to process the file with its own work', async () => {
    const connectors = await uploadJobImport(context, user, file, undefined);

    expect(connectors).toEqual(IMPORT_CONNECTORS);
    expect(mockPushToConnector).toHaveBeenCalledTimes(2);
    expect(mockPushToConnector).toHaveBeenCalledWith('connector-1', expect.objectContaining({
      internal: expect.objectContaining({ work_id: 'work-of-connector-1', applicant_id: 'user-1' }),
      event: expect.objectContaining({ file_id: 'import/global/report.json', file_mime: 'application/json' }),
    }));
    expect(mockPushToConnector).toHaveBeenCalledWith('connector-2', expect.objectContaining({
      internal: expect.objectContaining({ work_id: 'work-of-connector-2' }),
    }));
  });

  it('should not ask any connector when the work of one of them cannot be created', async () => {
    mockCreateWork.mockImplementation(async (_context, _user, connector) => {
      return connector.id === 'connector-2' ? undefined : { id: `work-of-${connector.id}` };
    });

    await expect(uploadJobImport(context, user, file, undefined)).rejects.toThrow('Unable to create connector work');
    expect(mockCreateWork).toHaveBeenCalledTimes(2);
    expect(mockPushToConnector).not.toHaveBeenCalled();
  });
});
