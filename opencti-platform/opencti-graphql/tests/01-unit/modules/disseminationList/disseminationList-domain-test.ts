import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as MiddlewareLoader from '../../../../src/database/middleware-loader';
import * as EnterpriseEdition from '../../../../src/enterprise-edition/ee';
import * as UserActionListener from '../../../../src/listener/UserActionListener';
import * as Smtp from '../../../../src/database/smtp';
import * as EntityRepresentative from '../../../../src/database/entity-representative';
import * as TelemetryManager from '../../../../src/manager/telemetryManager';
import * as FileStorage from '../../../../src/database/file-storage';
import * as RawFileStorage from '../../../../src/database/raw-file-storage';
import * as CacheModule from '../../../../src/database/cache';
import * as SafeEjs from '../../../../src/utils/safeEjs.client';
import { sendToDisseminationList } from '../../../../src/modules/disseminationList/disseminationList-domain';
import { ENTITY_TYPE_DISSEMINATION_LIST, type BasicStoreEntityDisseminationList } from '../../../../src/modules/disseminationList/disseminationList-types';
import type { DisseminationListSendInput } from '../../../../src/generated/graphql';

vi.mock('../../../../src/database/middleware-loader', () => ({
  internalLoadById: vi.fn(),
  pageEntitiesConnection: vi.fn(),
  storeLoadById: vi.fn(),
}));

vi.mock('../../../../src/enterprise-edition/ee', () => ({
  checkEnterpriseEdition: vi.fn(),
}));

vi.mock('../../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
  completeContextDataForEntity: vi.fn((inputContextData: object) => ({ ...inputContextData })),
}));

vi.mock('../../../../src/database/smtp', () => ({
  sendMail: vi.fn(),
  smtpComputeFrom: vi.fn(async () => 'platform@example.com'),
}));

vi.mock('../../../../src/database/entity-representative', () => ({
  extractEntityRepresentativeName: vi.fn(() => 'Entity representative name'),
}));

vi.mock('../../../../src/manager/telemetryManager', () => ({
  addDisseminationCount: vi.fn(),
}));

vi.mock('../../../../src/database/file-storage', () => ({
  loadFile: vi.fn(),
}));

vi.mock('../../../../src/database/raw-file-storage', () => ({
  downloadFile: vi.fn(),
  getFileContent: vi.fn(),
}));

vi.mock('../../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn(async () => ({ platform_title: 'OpenCTI' })),
}));

vi.mock('../../../../src/utils/safeEjs.client', () => ({
  safeRender: vi.fn(async () => '<html>rendered</html>'),
}));

vi.mock('../../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/config/conf')>();
  return {
    ...actual,
    default: {
      ...actual.default,
      get: (key: string) => (key === 'app:dissemination_list:to_email' ? 'dissemination@example.com' : actual.default.get(key)),
    },
    logApp: { info: vi.fn(), error: vi.fn(), debug: vi.fn(), warn: vi.fn() },
  };
});

const mockContext = { source: 'testing' } as any;
const mockUser = { id: 'user-1', user_email: 'user@example.com' } as any;

const makeDisseminationList = (overrides: Partial<BasicStoreEntityDisseminationList> = {}): BasicStoreEntityDisseminationList => ({
  id: 'dissemination-list-id',
  standard_id: 'dissemination-list--id-1',
  entity_type: ENTITY_TYPE_DISSEMINATION_LIST,
  name: 'My dissemination list',
  emails: ['a@example.com', 'b@example.com'],
  description: '',
  ...overrides,
} as unknown as BasicStoreEntityDisseminationList);

const makeInput = (overrides: Partial<DisseminationListSendInput> = {}): DisseminationListSendInput => ({
  entity_id: 'entity-id-1',
  use_octi_template: false,
  email_body: 'Hello world',
  email_object: 'Subject line',
  email_attachment_ids: [],
  html_to_body_file_id: null,
  ...overrides,
});

describe('sendToDisseminationList', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(EnterpriseEdition.checkEnterpriseEdition).mockResolvedValue(undefined as any);
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue(makeDisseminationList());
    vi.mocked(MiddlewareLoader.internalLoadById).mockResolvedValue({ id: 'entity-id-1', entity_type: 'Report' } as any);
    vi.mocked(Smtp.sendMail).mockResolvedValue(undefined as any);
    vi.mocked(Smtp.smtpComputeFrom).mockResolvedValue('platform@example.com');
    vi.mocked(EntityRepresentative.extractEntityRepresentativeName).mockReturnValue('Entity representative name');
    vi.mocked(UserActionListener.completeContextDataForEntity).mockImplementation((inputContextData: object) => ({ ...inputContextData } as any));
    vi.mocked(UserActionListener.publishUserAction).mockResolvedValue(undefined as any);
    vi.mocked(TelemetryManager.addDisseminationCount).mockResolvedValue(undefined as any);
    vi.mocked(CacheModule.getEntityFromCache).mockResolvedValue({ platform_title: 'OpenCTI' } as any);
    vi.mocked(SafeEjs.safeRender).mockResolvedValue('<html>rendered</html>');
  });

  it('sends the email and returns true on the happy path', async () => {
    const result = await sendToDisseminationList(mockContext, mockUser, 'dissemination-list-id', makeInput());

    expect(result).toBe(true);
    expect(Smtp.sendMail).toHaveBeenCalledTimes(1);
    expect(TelemetryManager.addDisseminationCount).toHaveBeenCalledTimes(1);
    expect(UserActionListener.publishUserAction).toHaveBeenCalledTimes(1);
  });

  it('bcc includes the dissemination list emails and the requesting user email', async () => {
    await sendToDisseminationList(mockContext, mockUser, 'dissemination-list-id', makeInput());

    const sendMailArgs = vi.mocked(Smtp.sendMail).mock.calls[0][0];
    expect(sendMailArgs.bcc).toStrictEqual(['a@example.com', 'b@example.com', 'user@example.com']);
    expect(sendMailArgs.subject).toBe('Subject line');
  });

  it('publishes a disseminate user action with the expected event metadata', async () => {
    await sendToDisseminationList(mockContext, mockUser, 'dissemination-list-id', makeInput());

    expect(UserActionListener.publishUserAction).toHaveBeenCalledWith(expect.objectContaining({
      event_access: 'administration',
      user: mockUser,
      event_type: 'file',
      event_scope: 'disseminate',
    }));
  });

  it('enriches the published context data with the dissemination list name and sent files', async () => {
    await sendToDisseminationList(mockContext, mockUser, 'dissemination-list-id', makeInput());

    const completeContextDataArgs = vi.mocked(UserActionListener.completeContextDataForEntity).mock.calls[0][0] as any;
    expect(completeContextDataArgs.input.dissemination).toBe('My dissemination list');
    expect(completeContextDataArgs.input.files).toStrictEqual([]);
    expect(completeContextDataArgs.id).toBe('entity-id-1');
  });

  it('checks the enterprise edition before doing anything else', async () => {
    await sendToDisseminationList(mockContext, mockUser, 'dissemination-list-id', makeInput());

    expect(EnterpriseEdition.checkEnterpriseEdition).toHaveBeenCalledWith(mockContext);
  });

  it('propagates the enterprise edition check failure and never sends the email', async () => {
    vi.mocked(EnterpriseEdition.checkEnterpriseEdition).mockRejectedValue(new Error('EE required'));

    await expect(sendToDisseminationList(mockContext, mockUser, 'dissemination-list-id', makeInput())).rejects.toThrow('EE required');
    expect(Smtp.sendMail).not.toHaveBeenCalled();
  });

  it('throws a FunctionalError when the dissemination list cannot be found', async () => {
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue(undefined as any);

    await expect(sendToDisseminationList(mockContext, mockUser, 'missing-id', makeInput()))
      .rejects.toThrow(/is not of type/);
    expect(Smtp.sendMail).not.toHaveBeenCalled();
  });

  it('throws a FunctionalError when the loaded entity is not a dissemination list', async () => {
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue(makeDisseminationList({ entity_type: 'Report' } as any));

    await expect(sendToDisseminationList(mockContext, mockUser, 'dissemination-list-id', makeInput()))
      .rejects.toThrow(/is not of type/);
    expect(Smtp.sendMail).not.toHaveBeenCalled();
  });

  it('throws an UnsupportedError when the target entity cannot be found', async () => {
    vi.mocked(MiddlewareLoader.internalLoadById).mockResolvedValue(undefined as any);

    await expect(sendToDisseminationList(mockContext, mockUser, 'dissemination-list-id', makeInput()))
      .rejects.toThrow(/Cant find base element of dissemination/);
    expect(Smtp.sendMail).not.toHaveBeenCalled();
  });

  it('propagates errors raised while sending the email and skips the user action', async () => {
    vi.mocked(Smtp.sendMail).mockRejectedValue(new Error('SMTP down'));

    await expect(sendToDisseminationList(mockContext, mockUser, 'dissemination-list-id', makeInput())).rejects.toThrow('SMTP down');
    expect(UserActionListener.publishUserAction).not.toHaveBeenCalled();
    expect(TelemetryManager.addDisseminationCount).not.toHaveBeenCalled();
  });

  it('rejects attachments whose mimetype is not allowed for dissemination', async () => {
    vi.mocked(FileStorage.loadFile).mockResolvedValue({ id: 'file-1', name: 'malware.exe', metaData: { mimetype: 'application/x-msdownload' } } as any);

    await expect(sendToDisseminationList(
      mockContext,
      mockUser,
      'dissemination-list-id',
      makeInput({ email_attachment_ids: ['file-1'] }),
    )).rejects.toThrow(/File cant be disseminate/);
    expect(Smtp.sendMail).not.toHaveBeenCalled();
  });

  it('attaches allowed files and includes them in the sent files list', async () => {
    vi.mocked(FileStorage.loadFile).mockResolvedValue({ id: 'file-1', name: 'report.pdf', metaData: { mimetype: 'application/pdf' } } as any);
    vi.mocked(RawFileStorage.downloadFile).mockResolvedValue('file-stream' as any);

    await sendToDisseminationList(mockContext, mockUser, 'dissemination-list-id', makeInput({ email_attachment_ids: ['file-1'] }));

    const sendMailArgs = vi.mocked(Smtp.sendMail).mock.calls[0][0];
    expect(sendMailArgs.attachments).toStrictEqual([{ filename: 'report.pdf', content: 'file-stream' }]);
    const completeContextDataArgs = vi.mocked(UserActionListener.completeContextDataForEntity).mock.calls[0][0] as any;
    expect(completeContextDataArgs.input.files).toHaveLength(1);
  });
});
