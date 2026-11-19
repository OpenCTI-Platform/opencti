import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as middleware from '../../../src/database/middleware';
import * as stixCoreObject from '../../../src/domain/stixCoreObject';
import { externalReferenceImportPushRef } from '../../../src/domain/externalReference';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import type { BasicStoreEntity } from '../../../src/types/store';
import type { LoadedFile } from '../../../src/database/file-storage';
import type { FileRefInput } from '../../../src/generated/graphql';

describe('external reference domain import push ref', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const FILE_REF: FileRefInput = {
    sync_id: 'sync--1',
    storage_key: 'sync/inflight/sync--1/0123456789abcdef0123456789abcdef/content',
    name: 'report.pdf',
  };

  const COPIED_FILE: LoadedFile = {
    id: 'import/External-Reference/external-reference--1/report.pdf',
    name: 'report.pdf',
    size: 3,
    information: '',
    lastModified: new Date(0),
    lastModifiedSinceMin: 0,
    metaData: {},
    uploadStatus: 'complete',
  };

  it('gives the domain objects citing the external reference as the import context, like importPush', async () => {
    const citingReport = { internal_id: 'report--1', entity_type: 'Report' } as unknown as BasicStoreEntity;
    const listSpy = vi.spyOn(middleware, 'topEntitiesOrRelationsList').mockResolvedValue([citingReport]);
    const pushRefSpy = vi.spyOn(stixCoreObject, 'stixCoreObjectImportPushRef').mockResolvedValue(COPIED_FILE);

    await externalReferenceImportPushRef(testContext, ADMIN_USER, 'external-reference--1', FILE_REF);

    expect(listSpy).toHaveBeenCalledWith(testContext, ADMIN_USER, ['Stix-Domain-Object'], expect.objectContaining({ first: 50 }));
    expect(JSON.stringify(listSpy.mock.calls[0][3])).toContain('external-reference--1');
    expect(pushRefSpy).toHaveBeenCalledWith(testContext, ADMIN_USER, 'external-reference--1', FILE_REF, [citingReport]);
  });
});
