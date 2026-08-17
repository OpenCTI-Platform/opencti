import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as middleware from '../../../src/database/middleware';
import * as fileStorage from '../../../src/database/file-storage';
import * as access from '../../../src/utils/access';
import * as draftContext from '../../../src/utils/draftContext';
import * as identifier from '../../../src/schema/identifier';
import * as masterLock from '../../../src/lock/master-lock';
import * as entitySettingUtils from '../../../src/modules/entitySetting/entitySetting-utils';
import { stixCoreObjectImportPush } from '../../../src/domain/stixCoreObject';

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
    vi.spyOn(draftContext, 'getDraftContext').mockReturnValue(null);
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

    expect(result.id).toEqual('file--1');
    expect(uploadSpy.mock.calls[0][2]).toEqual('fromTemplate/Report/report--1');
    expect(uploadSpy.mock.calls[0][4].meta.fintel_template_id).toEqual('fintel-template--1');
    expect(unlock).toHaveBeenCalledTimes(1);
  });

  it('should not store fintel template id metadata for standard uploads', async () => {
    const { uploadSpy } = setupImportPush();
    const file = Promise.resolve({ filename: 'export.pdf' } as never);

    await stixCoreObjectImportPush({}, { id: 'user--1' } as never, 'report--1', file, {
      fromTemplate: false,
      fintelTemplateId: 'fintel-template--1',
    });

    expect(uploadSpy.mock.calls[0][2]).toEqual('import/Report/report--1');
    expect(uploadSpy.mock.calls[0][4].meta.fintel_template_id).toBeUndefined();
  });
});
