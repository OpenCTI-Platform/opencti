import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as middleware from '../../../src/database/middleware';
import * as middlewareLoader from '../../../src/database/middleware-loader';
import * as fileStorage from '../../../src/database/file-storage';
import * as access from '../../../src/utils/access';
import * as draftContext from '../../../src/utils/draftContext';
import * as identifier from '../../../src/schema/identifier';
import * as masterLock from '../../../src/lock/master-lock';
import * as entitySettingUtils from '../../../src/modules/entitySetting/entitySetting-utils';
import * as userActionListener from '../../../src/listener/UserActionListener';
import * as work from '../../../src/domain/work';
import * as streamHandler from '../../../src/database/stream/stream-handler';
import { batchInternalRels, stixCoreObjectExportPush, stixCoreObjectImportPush, stixCoreObjectImportPushRef, stixCoreObjectsExportPush } from '../../../src/domain/stixCoreObject';
import type { BasicStoreEntity } from '../../../src/types/store';
import type { FileRefInput } from '../../../src/generated/graphql';
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../../../src/schema/stixMetaObject';

describe('stix core object domain import push', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const setupImportPush = () => {
    vi.spyOn(middleware, 'storeLoadByIdWithRefs').mockResolvedValue({
      _index: 'index-test',
      _id: 'doc-test',
      internal_id: 'report--1',
      entity_type: 'Report',
      x_opencti_files: [],
    } as never);
    vi.spyOn(access, 'validateUserAccessOperation').mockReturnValue(true);
    vi.spyOn(draftContext, 'getDraftContext').mockReturnValue(undefined);
    vi.spyOn(identifier, 'getInstanceIds').mockReturnValue(['report--1']);
    vi.spyOn(entitySettingUtils, 'getEntitySettingFromCache').mockResolvedValue({ platform_entity_files_ref: false } as never);
    const unlock = vi.fn();
    vi.spyOn(masterLock, 'lockResources').mockResolvedValue({ unlock } as never);
    const uploadSpy = vi.spyOn(fileStorage, 'uploadToStorage').mockResolvedValue({
      upload: { id: 'file--1' },
      untouched: true,
    } as never);
    return { uploadSpy, unlock };
  };

  it('should store fintel template id metadata for fromTemplate uploads', async () => {
    const { uploadSpy, unlock } = setupImportPush();
    const file = Promise.resolve({ filename: 'export.pdf' } as never);

    const result = await stixCoreObjectImportPush({}, { id: 'user--1' } as never, 'report--1', file, {
      fromTemplate: true,
      fintelTemplateId: 'fintel-template--1',
    });

    const uploadOptions = uploadSpy.mock.calls[0]?.[4] as { meta?: { fintel_template_id?: string } } | undefined;
    expect(result.id).toEqual('file--1');
    expect(uploadSpy.mock.calls[0][2]).toEqual('fromTemplate/Report/report--1');
    expect(uploadOptions?.meta?.fintel_template_id).toEqual('fintel-template--1');
    expect(unlock).toHaveBeenCalledTimes(1);
  });

  it('should not store fintel template id metadata for standard uploads', async () => {
    const { uploadSpy } = setupImportPush();
    const file = Promise.resolve({ filename: 'export.pdf' } as never);

    await stixCoreObjectImportPush({}, { id: 'user--1' } as never, 'report--1', file, {
      fromTemplate: false,
      fintelTemplateId: 'fintel-template--1',
    });

    const uploadOptions = uploadSpy.mock.calls[0]?.[4] as { meta?: { fintel_template_id?: string } } | undefined;
    expect(uploadSpy.mock.calls[0][2]).toEqual('import/Report/report--1');
    expect(uploadOptions?.meta?.fintel_template_id).toBeUndefined();
  });
});

describe('stix core object domain import push ref', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const REPORT = { _index: 'index-test', _id: 'doc-test', internal_id: 'report--1', entity_type: 'Report', x_opencti_files: [] } as unknown as BasicStoreEntity;
  const FILE_REF: FileRefInput = {
    sync_id: 'sync--1',
    storage_key: 'sync/inflight/sync--1/0123456789abcdef0123456789abcdef/content',
    name: 'report.pdf',
    mime_type: 'application/pdf',
    version: new Date('2024-01-01T00:00:00.000Z'),
    file_markings: ['marking--1'],
    no_trigger_import: true,
  };

  const setupImportPushRef = () => {
    vi.spyOn(middleware, 'storeLoadByIdWithRefs').mockResolvedValue(REPORT as never);
    vi.spyOn(access, 'validateUserAccessOperation').mockReturnValue(true);
    vi.spyOn(draftContext, 'getDraftContext').mockReturnValue(undefined);
    vi.spyOn(identifier, 'getInstanceIds').mockReturnValue(['report--1']);
    vi.spyOn(entitySettingUtils, 'getEntitySettingFromCache').mockResolvedValue({ platform_entity_files_ref: true } as never);
    const unlock = vi.fn();
    const lockSpy = vi.spyOn(masterLock, 'lockResources').mockResolvedValue({ unlock } as never);
    const uploadSpy = vi.spyOn(fileStorage, 'uploadToStorage');
    const copySpy = vi.spyOn(fileStorage, 'copyFileFromSyncReference').mockResolvedValue({ upload: { id: 'file--1' }, untouched: true } as never);
    const updateEventSpy = vi.spyOn(streamHandler, 'storeUpdateEvent');
    return { unlock, lockSpy, uploadSpy, copySpy, updateEventSpy };
  };

  it('copies the staged file with the options importPush would upload it with', async () => {
    const { uploadSpy, copySpy } = setupImportPushRef();

    const result = await stixCoreObjectImportPushRef({}, { id: 'user--1' } as never, 'report--1', FILE_REF, undefined);

    expect(result.id).toEqual('file--1');
    expect(uploadSpy).not.toHaveBeenCalled();
    expect(copySpy).toHaveBeenCalledWith({}, { id: 'user--1' }, {
      syncId: 'sync--1',
      filePath: 'import/Report/report--1',
      storageKey: FILE_REF.storage_key,
      name: 'report.pdf',
      mimeType: 'application/pdf',
      version: '2024-01-01T00:00:00.000Z',
      fileMarkings: ['marking--1'],
      entityId: 'report--1',
      externalReferenceId: identifier.generateStandardId(ENTITY_TYPE_EXTERNAL_REFERENCE, { url: '/storage/get/import/Report/report--1/report.pdf' }),
      noTriggerImport: true,
      importContextEntities: [REPORT],
    });
  });

  it('keeps the import context entities given by the caller', async () => {
    const { copySpy } = setupImportPushRef();
    const container = { internal_id: 'container--1', entity_type: 'Report' } as unknown as BasicStoreEntity;

    await stixCoreObjectImportPushRef({}, { id: 'user--1' } as never, 'report--1', FILE_REF, [container]);

    expect(copySpy.mock.calls[0][2].importContextEntities).toEqual([container]);
  });

  it('copies while the entity is locked', async () => {
    const { unlock, lockSpy, copySpy } = setupImportPushRef();

    await stixCoreObjectImportPushRef({}, { id: 'user--1' } as never, 'report--1', FILE_REF, undefined);

    expect(lockSpy.mock.invocationCallOrder[0]).toBeLessThan(copySpy.mock.invocationCallOrder[0]);
    expect(copySpy.mock.invocationCallOrder[0]).toBeLessThan(unlock.mock.invocationCallOrder[0]);
  });

  it('publishes no stream event when the copy leaves the file untouched', async () => {
    const { updateEventSpy } = setupImportPushRef();

    await stixCoreObjectImportPushRef({}, { id: 'user--1' } as never, 'report--1', FILE_REF, undefined);

    expect(updateEventSpy).not.toHaveBeenCalled();
  });

  it('fails with only the sync id in the error data when the copy is refused, and still unlocks', async () => {
    const { unlock, copySpy, updateEventSpy } = setupImportPushRef();
    copySpy.mockResolvedValue(null);

    const importPushRef = stixCoreObjectImportPushRef({}, { id: 'user--1' } as never, 'report--1', FILE_REF, undefined);

    await expect(importPushRef).rejects.toThrow('Cannot copy referenced sync file');
    await expect(importPushRef).rejects.toHaveProperty('extensions.data', { http_status: 400, genre: 'BUSINESS', syncId: 'sync--1' });
    expect(updateEventSpy).not.toHaveBeenCalled();
    expect(unlock).toHaveBeenCalledTimes(1);
  });
});

describe('stix core object domain export push', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const setupExportPush = (applicantId: string | undefined) => {
    vi.spyOn(middleware, 'storeLoadByIdWithRefs').mockResolvedValue({ internal_id: 'report--1', entity_type: 'Report' } as never);
    vi.spyOn(middlewareLoader, 'internalLoadById').mockResolvedValue({ internal_id: 'report--1', entity_type: 'Report' } as never);
    vi.spyOn(userActionListener, 'publishUserAction').mockResolvedValue(true as never);
    const applicantSpy = vi.spyOn(work, 'findExportApplicantId').mockResolvedValue(applicantId);
    const uploadSpy = vi.spyOn(fileStorage, 'uploadToStorage').mockResolvedValue({
      upload: { id: 'file--1', name: 'export.json' },
      untouched: false,
    } as never);
    return { applicantSpy, uploadSpy };
  };

  it('should register the user who asked for an entity export as file creator', async () => {
    const { applicantSpy, uploadSpy } = setupExportPush('applicant--1');
    const file = Promise.resolve({ filename: 'export.json' } as never);

    await stixCoreObjectExportPush({}, { id: 'connector-user--1' } as never, 'report--1', { file, file_markings: [] });

    expect(applicantSpy).toHaveBeenCalledWith({}, { id: 'connector-user--1' }, 'export/Report/report--1', 'export.json');
    expect(uploadSpy.mock.calls[0][2]).toEqual('export/Report/report--1');
    expect((uploadSpy.mock.calls[0][4] as { creatorId?: string }).creatorId).toEqual('applicant--1');
  });

  it('should register the user who asked for a list export as file creator', async () => {
    const { applicantSpy, uploadSpy } = setupExportPush('applicant--1');
    const file = Promise.resolve({ filename: 'export.json' } as never);

    await stixCoreObjectsExportPush({}, { id: 'connector-user--1' } as never, undefined, 'Report', file, [], null);

    expect(applicantSpy).toHaveBeenCalledWith({}, { id: 'connector-user--1' }, 'export/Report', 'export.json');
    expect(uploadSpy.mock.calls[0][2]).toEqual('export/Report');
    expect((uploadSpy.mock.calls[0][4] as { creatorId?: string }).creatorId).toEqual('applicant--1');
  });

  it('should leave the creator to the uploading user when no export work matches', async () => {
    const { uploadSpy } = setupExportPush(undefined);
    const file = Promise.resolve({ filename: 'export.json' } as never);

    await stixCoreObjectExportPush({}, { id: 'connector-user--1' } as never, 'report--1', { file, file_markings: [] });

    expect((uploadSpy.mock.calls[0][4] as { creatorId?: string }).creatorId).toBeUndefined();
  });
});

describe('batchInternalRels', () => {
  const mockContext = {} as never;
  const mockUser = { id: 'user--1' } as never;

  const author = {
    id: 'org--internal-id',
    internal_id: 'org--internal-id',
    standard_id: 'identity--d4551de9-4b9c-570e-a51c-d3c321eb9a8d',
    entity_type: 'Organization',
    parent_types: ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object', 'Identity'],
    name: 'Secret Org',
  };

  const createdByDefinition = {
    databaseName: 'rel_created-by.internal_id',
    multiple: false,
    toTypes: ['Organization'],
  } as any;

  const objectsDefinition = {
    databaseName: 'rel_object.internal_id',
    multiple: true,
    toTypes: ['Organization'],
  } as any;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('returns the real author when the user has access', async () => {
    vi.spyOn(middlewareLoader, 'internalFindByIds').mockResolvedValue({ [author.internal_id]: author } as never);
    vi.spyOn(access, 'isUserCanAccessStoreElement').mockResolvedValue(true);

    const element = { [createdByDefinition.databaseName]: author.internal_id };
    const [result] = await batchInternalRels(mockContext, mockUser, [{ element, definition: createdByDefinition }]);

    expect(result).toEqual(author);
  });

  it('returns a restricted author with an obfuscated standard_id when access is denied', async () => {
    vi.spyOn(middlewareLoader, 'internalFindByIds').mockResolvedValue({ [author.internal_id]: author } as never);
    vi.spyOn(access, 'isUserCanAccessStoreElement').mockResolvedValue(false);

    const element = { [createdByDefinition.databaseName]: author.internal_id };
    const [result] = await batchInternalRels(mockContext, mockUser, [{ element, definition: createdByDefinition }]);

    expect(result.name).toBe('Restricted');
    // standard_id must stay obfuscated: pycti drops restricted createdBy refs
    // entirely from STIX exports, so exposing the real id here would only leak
    // the entity's identity to a user with no access to it.
    expect(result.standard_id).toBe('Restricted');
  });

  it('restricts individual entries within a multiple ref while keeping standard_id obfuscated', async () => {
    const secondAuthor = {
      ...author,
      id: 'org--internal-id-2',
      internal_id: 'org--internal-id-2',
      standard_id: 'identity--2c3b6ef1-3e0d-5a3b-9a3a-7a7f5b0f6b2a',
      name: 'Visible Org',
    };
    vi.spyOn(middlewareLoader, 'internalFindByIds').mockResolvedValue({
      [author.internal_id]: author,
      [secondAuthor.internal_id]: secondAuthor,
    } as never);
    vi.spyOn(access, 'isUserCanAccessStoreElement').mockImplementation(async (_ctx, _user, resolved: any) => {
      return resolved.internal_id === secondAuthor.internal_id;
    });

    const element = { [objectsDefinition.databaseName]: [author.internal_id, secondAuthor.internal_id] };
    const [result] = await batchInternalRels(mockContext, mockUser, [{ element, definition: objectsDefinition }]);

    expect(result).toHaveLength(2);
    const restricted = result.find((e: any) => e.id === author.internal_id) as any;
    const visible = result.find((e: any) => e.internal_id === secondAuthor.internal_id);

    expect(restricted.name).toBe('Restricted');
    expect(restricted.standard_id).toBe('Restricted');
    expect(visible).toEqual(secondAuthor);
  });
});
