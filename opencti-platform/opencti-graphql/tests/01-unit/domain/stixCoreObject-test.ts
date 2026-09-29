import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as middleware from '../../../src/database/middleware';
import * as middlewareLoader from '../../../src/database/middleware-loader';
import * as fileStorage from '../../../src/database/file-storage';
import * as access from '../../../src/utils/access';
import * as draftContext from '../../../src/utils/draftContext';
import * as identifier from '../../../src/schema/identifier';
import * as masterLock from '../../../src/lock/master-lock';
import * as entitySettingUtils from '../../../src/modules/entitySetting/entitySetting-utils';
import * as engine from '../../../src/database/engine';
import * as streamHandler from '../../../src/database/stream/stream-handler';
import * as userActionListener from '../../../src/listener/UserActionListener';
import { batchInternalRels, stixCoreObjectImportPush, stixCoreObjectImportPushRef } from '../../../src/domain/stixCoreObject';

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

describe('stix core object domain import push ref (sync file reference mode)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const setupImportPushRef = (isAutoExternal = false) => {
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
    vi.spyOn(entitySettingUtils, 'getEntitySettingFromCache').mockResolvedValue({ platform_entity_files_ref: isAutoExternal } as never);
    const unlock = vi.fn();
    vi.spyOn(masterLock, 'lockResources').mockResolvedValue({ unlock } as never);
    vi.spyOn(engine, 'elUpdateElement').mockResolvedValue(undefined as never);
    vi.spyOn(engine, 'elFindByIds').mockResolvedValue({} as never);
    vi.spyOn(streamHandler, 'storeUpdateEvent').mockResolvedValue(undefined as never);
    vi.spyOn(userActionListener, 'publishUserAction').mockResolvedValue(undefined as never);
    const copySpy = vi.spyOn(fileStorage, 'copyFileFromSyncReference').mockResolvedValue({
      upload: {
        id: 'import/Report/report--1/report.pdf',
        name: 'report.pdf',
        metaData: { version: '2024-01-01T00:00:00.000Z', mimetype: 'application/pdf', file_markings: ['marking--1'] },
      },
      untouched: false,
    } as never);
    return { copySpy, unlock };
  };

  const fileRef = {
    sync_id: 'sync--1',
    storage_key: 'sync/inflight/sync--1/remote-file-1/content',
    name: 'report.pdf',
    mime_type: 'application/pdf',
    file_markings: ['marking--1'],
  };

  it('copies via the sync reference instead of uploading a stream, using the caller-supplied sync_id for ownership validation', async () => {
    const { copySpy, unlock } = setupImportPushRef();

    const result = await stixCoreObjectImportPushRef({}, { id: 'user--1' } as never, 'report--1', fileRef);

    expect(result.id).toEqual('import/Report/report--1/report.pdf');
    expect(copySpy).toHaveBeenCalledTimes(1);
    const [, , calledSyncId, calledFilePath, calledCopyProps] = copySpy.mock.calls[0];
    expect(calledSyncId).toEqual('sync--1');
    expect(calledFilePath).toEqual('import/Report/report--1');
    expect(calledCopyProps).toMatchObject({
      storageKey: 'sync/inflight/sync--1/remote-file-1/content',
      name: 'report.pdf',
      mimeType: 'application/pdf',
      fileMarkings: ['marking--1'],
      entityId: 'report--1',
      noTriggerImport: undefined,
      importContextEntities: [{ internal_id: 'report--1', entity_type: 'Report' }],
    });
    expect(unlock).toHaveBeenCalledTimes(1);
  });

  it('forwards no_trigger_import from the fileRef so enrichment is skipped on the copy path too', async () => {
    const { copySpy } = setupImportPushRef();

    await stixCoreObjectImportPushRef({}, { id: 'user--1' } as never, 'report--1', { ...fileRef, no_trigger_import: true });

    const [, , , , calledCopyProps] = copySpy.mock.calls[0];
    expect((calledCopyProps as { noTriggerImport?: boolean }).noTriggerImport).toEqual(true);
  });

  it('never derives the ownership-check sync_id from the storage_key itself - only from the caller-supplied fileRef.sync_id', async () => {
    const { copySpy } = setupImportPushRef();
    const maliciousFileRef = { ...fileRef, sync_id: 'sync--attacker', storage_key: 'sync/inflight/sync--victim/remote-file-1/content' };

    await stixCoreObjectImportPushRef({}, { id: 'user--1' } as never, 'report--1', maliciousFileRef);

    // The function must pass through exactly what the caller declared as sync_id (validation/rejection
    // of a mismatch is copyFileFromSyncReference's job, already covered in its own test suite).
    const [, , calledSyncId] = copySpy.mock.calls[0];
    expect(calledSyncId).toEqual('sync--attacker');
  });

  it('throws when the reference copy fails, instead of silently proceeding to attach a non-existent file', async () => {
    setupImportPushRef();
    vi.spyOn(fileStorage, 'copyFileFromSyncReference').mockResolvedValue(null);

    await expect(stixCoreObjectImportPushRef({}, { id: 'user--1' } as never, 'report--1', fileRef))
      .rejects.toThrow('Cannot copy referenced sync file');
  });

  it('passes a deterministic external_reference_id through to the copy when the entity setting requires it', async () => {
    const { copySpy } = setupImportPushRef(true);

    // The isAutoExternal branch also creates+links an ExternalReference entity, which needs a much
    // heavier DB mock stack unrelated to this test's concern; we only care what copyFileFromSyncReference
    // was called with, so tolerate (not assert on) whatever happens afterwards.
    await stixCoreObjectImportPushRef({}, { id: 'user--1' } as never, 'report--1', fileRef).catch(() => {});

    const [, , , , calledCopyProps] = copySpy.mock.calls[0];
    expect((calledCopyProps as { externalReferenceId?: string }).externalReferenceId).toBeDefined();
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
