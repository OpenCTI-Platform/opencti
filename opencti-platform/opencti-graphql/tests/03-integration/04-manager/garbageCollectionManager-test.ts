import { describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { purgeTrashIfMainEntityLive } from '../../../src/manager/garbageCollectionManager';
import { buildEntityData } from '../../../src/database/data-builder';
import { elDeleteElements, elDeleteInstances, elFindByIds, elIndex, elIndexElements, elReindexElements } from '../../../src/database/engine';
import { INDEX_DELETED_OBJECTS, INDEX_FILES, READ_DATA_INDICES, READ_INDEX_DELETED_OBJECTS, READ_INDEX_FILES } from '../../../src/database/utils';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';
import { generateInternalId } from '../../../src/schema/identifier';
import { type BasicStoreEntityDeleteOperation, ENTITY_TYPE_DELETE_OPERATION } from '../../../src/modules/deleteOperation/deleteOperation-types';
import type { BasicStoreBase } from '../../../src/types/store';

type BuiltEntity = { element: Record<string, any> };

// Everything is written at engine level: no stream event is generated, stream and sync counters are not impacted
const createReportInTrash = async (name: string) => {
  const reportInput = { entity_type: ENTITY_TYPE_CONTAINER_REPORT, name, published: '2020-02-26T00:51:35.000Z' };
  const { element: report } = await buildEntityData(testContext, ADMIN_USER, reportInput, ENTITY_TYPE_CONTAINER_REPORT) as BuiltEntity;
  await elIndexElements(testContext, ADMIN_USER, ENTITY_TYPE_CONTAINER_REPORT, [report]);
  const [liveReport] = await elFindByIds(testContext, ADMIN_USER, [report.internal_id], { indices: READ_DATA_INDICES }) as BasicStoreBase[];
  // Copy to the trash, as the first step of a deletion does
  await elReindexElements(testContext, ADMIN_USER, [liveReport.internal_id], liveReport._index, INDEX_DELETED_OBJECTS);
  const deleteOperationInput = {
    entity_type: ENTITY_TYPE_DELETE_OPERATION,
    main_entity_type: ENTITY_TYPE_CONTAINER_REPORT,
    main_entity_id: liveReport.internal_id,
    main_entity_name: name,
    deleted_elements: [{ id: liveReport.internal_id, source_index: liveReport._index }],
    confidence: 100,
  };
  const { element: deleteOperationElement } = await buildEntityData(testContext, ADMIN_USER, deleteOperationInput, ENTITY_TYPE_DELETE_OPERATION) as BuiltEntity;
  await elIndexElements(testContext, ADMIN_USER, ENTITY_TYPE_DELETE_OPERATION, [deleteOperationElement]);
  const deleteOperationId = deleteOperationElement.internal_id;
  const deleteOperation = await storeLoadById(testContext, ADMIN_USER, deleteOperationId, ENTITY_TYPE_DELETE_OPERATION) as unknown as BasicStoreEntityDeleteOperation;
  return { liveReport, deleteOperation };
};

const findInTrash = async (id: string) => elFindByIds(testContext, ADMIN_USER, [id], { indices: READ_INDEX_DELETED_OBJECTS }) as Promise<BasicStoreBase[]>;
const findLive = async (id: string) => elFindByIds(testContext, ADMIN_USER, [id], { indices: READ_DATA_INDICES }) as Promise<BasicStoreBase[]>;

describe('Garbage collection manager', () => {
  it('should only purge the trash when the main entity is also live', async () => {
    // Interrupted deletion: report copied to the trash but still live
    const { liveReport, deleteOperation } = await createReportInTrash('GC report still live');
    // Indexed file of the report, flagged as removed by the interrupted deletion
    const fileDocId = generateInternalId();
    await elIndex(INDEX_FILES, {
      internal_id: fileDocId,
      file_id: `import/Report/${liveReport.internal_id}/gc-test.txt`,
      name: 'gc-test.txt',
      entity_id: liveReport.internal_id,
      entity_type: ENTITY_TYPE_CONTAINER_REPORT,
      removed: true,
    });
    expect((await findInTrash(liveReport.internal_id)).length).toBe(1);
    expect((await findLive(liveReport.internal_id)).length).toBe(1);

    const isPurged = await purgeTrashIfMainEntityLive(testContext, deleteOperation);
    expect(isPurged).toBe(true);

    // Trash copy and delete operation removed, live report untouched
    expect((await findInTrash(liveReport.internal_id)).length).toBe(0);
    expect(await storeLoadById(testContext, ADMIN_USER, deleteOperation.id, ENTITY_TYPE_DELETE_OPERATION)).toBeFalsy();
    expect((await findLive(liveReport.internal_id)).length).toBe(1);
    // Report file searchable again
    const [fileDoc] = await elFindByIds(testContext, ADMIN_USER, [fileDocId], { indices: READ_INDEX_FILES }) as (BasicStoreBase & { removed: boolean })[];
    expect(fileDoc.removed).toBe(false);

    // Cleanup
    await elDeleteInstances(testContext, [fileDoc]);
    await elDeleteElements(testContext, ADMIN_USER, [liveReport]);
  });

  it('should not purge anything when the main entity is only in the trash', async () => {
    // Normal deletion: report only in the trash
    const { liveReport, deleteOperation } = await createReportInTrash('GC report only in trash');
    await elDeleteInstances(testContext, [liveReport]);
    expect((await findLive(liveReport.internal_id)).length).toBe(0);

    const isPurged = await purgeTrashIfMainEntityLive(testContext, deleteOperation);
    expect(isPurged).toBe(false);

    // Nothing touched, the regular confirm delete keeps handling it
    expect((await findInTrash(liveReport.internal_id)).length).toBe(1);
    expect(await storeLoadById(testContext, ADMIN_USER, deleteOperation.id, ENTITY_TYPE_DELETE_OPERATION)).toBeTruthy();

    // Cleanup
    await elDeleteInstances(testContext, await findInTrash(liveReport.internal_id));
    await elDeleteElements(testContext, ADMIN_USER, [deleteOperation]);
  });
});
