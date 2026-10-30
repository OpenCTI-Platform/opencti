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
import { batchInternalRels, stixCoreObjectExportPush, stixCoreObjectImportPush, stixCoreObjectsExportPush } from '../../../src/domain/stixCoreObject';

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
