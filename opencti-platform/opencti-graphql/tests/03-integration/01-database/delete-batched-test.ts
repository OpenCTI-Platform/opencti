import { describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { buildEntityData, buildRelationData } from '../../../src/database/data-builder';
import { elCount, elDeleteElements, elFindByIds, elIndexElements, elMarkElementsAsDraftDelete } from '../../../src/database/engine';
import { READ_DATA_INDICES, READ_ENTITIES_INDICES, READ_RELATIONSHIPS_INDICES } from '../../../src/database/utils';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';
import { ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { RELATION_RELATED_TO } from '../../../src/schema/stixCoreRelationship';
import { ABSTRACT_BASIC_RELATIONSHIP } from '../../../src/schema/general';
import { FilterMode } from '../../../src/generated/graphql';
import type { BasicStoreBase } from '../../../src/types/store';

type Built = { element: Record<string, any>; relations?: Record<string, any>[] };

// Everything is written at engine level: no stream event is generated, stream and sync counters are not impacted
const indexEntity = async (input: Record<string, any>) => {
  const { element, relations } = await buildEntityData(testContext, ADMIN_USER, input, input.entity_type) as Built;
  await elIndexElements(testContext, ADMIN_USER, input.entity_type, [element, ...(relations ?? [])]);
  return element;
};
const indexRelation = async (input: Record<string, any>) => {
  const { element, relations } = await buildRelationData(testContext, ADMIN_USER, input) as Built;
  await elIndexElements(testContext, ADMIN_USER, input.relationship_type, [element, ...(relations ?? [])]);
  return element;
};
const findLive = async (id: string) => elFindByIds(testContext, ADMIN_USER, [id], { indices: READ_DATA_INDICES }) as Promise<BasicStoreBase[]>;
const countConnectedRelations = (id: string) => elCount(testContext, ADMIN_USER, READ_RELATIONSHIPS_INDICES, {
  types: [ABSTRACT_BASIC_RELATIONSHIP],
  filters: { mode: FilterMode.And, filters: [{ key: ['connections'], nested: [{ key: 'internal_id', values: [id] }], values: [] }], filterGroups: [] },
});
// Uses the denormalized rel_created-by of the entities, the field the delete must clean up
const countAuthoredMalwares = (authorId: string) => elCount(testContext, ADMIN_USER, READ_ENTITIES_INDICES, {
  types: [ENTITY_TYPE_MALWARE],
  filters: { mode: FilterMode.And, filters: [{ key: ['createdBy'], values: [authorId] }], filterGroups: [] },
});

const MALWARES_COUNT = 7;
// An author with more relations than a page:
// - one created-by per malware,
// - a related-to between a malware and the author, itself authored: its created-by is connected to the author AND to the related-to
const createAuthorWithRelations = async (name: string) => {
  const author = await indexEntity({ entity_type: ENTITY_TYPE_IDENTITY_ORGANIZATION, name, identity_class: 'organization' });
  const malwares = [];
  for (let i = 0; i < MALWARES_COUNT; i += 1) {
    malwares.push(await indexEntity({ entity_type: ENTITY_TYPE_MALWARE, name: `${name} malware ${i}`, createdBy: author }));
  }
  const relatedTo = await indexRelation({ relationship_type: RELATION_RELATED_TO, from: malwares[0], to: author, createdBy: author });
  const [loadedAuthor] = await findLive(author.internal_id);
  return { author: loadedAuthor, malwares, relatedTo };
};

describe('Batched delete of heavily-referenced elements', () => {
  it('should delete an author and all its relations page by page, cleaning up the elements that remain', async () => {
    const { author, malwares, relatedTo } = await createAuthorWithRelations('Batched delete author');
    expect(await countConnectedRelations(author.internal_id)).toBe(MALWARES_COUNT + 2);
    expect(await countAuthoredMalwares(author.internal_id)).toBe(MALWARES_COUNT);

    // Pages of 2: several pages for the author, and the created-by of the related-to is reached twice
    await elDeleteElements(testContext, ADMIN_USER, [author], { batchSize: 2 });

    expect(await findLive(author.internal_id)).toHaveLength(0);
    expect(await findLive(relatedTo.internal_id)).toHaveLength(0);
    expect(await countConnectedRelations(author.internal_id)).toBe(0);
    // The malwares remain, without the author in their denormalized created-by
    expect(await countAuthoredMalwares(author.internal_id)).toBe(0);
    for (let i = 0; i < malwares.length; i += 1) {
      expect(await findLive(malwares[i].internal_id)).toHaveLength(1);
    }

    // Cleanup
    const liveMalwares = await elFindByIds(testContext, ADMIN_USER, malwares.map((m) => m.internal_id), { indices: READ_DATA_INDICES }) as BasicStoreBase[];
    await elDeleteElements(testContext, ADMIN_USER, liveMalwares);
  });

  it('should refuse to move an element to the trash above the snapshot cap, without changing anything', async () => {
    const { author, malwares } = await createAuthorWithRelations('Trash capped author');

    const trashDelete = elDeleteElements(testContext, ADMIN_USER, [author], { forceDelete: false, maxSnapshotRelations: 3 });
    await expect(trashDelete).rejects.toThrow('Cannot move element to trash: too many related relations, delete it permanently');

    expect(await findLive(author.internal_id)).toHaveLength(1);
    expect(await countConnectedRelations(author.internal_id)).toBe(MALWARES_COUNT + 2);
    expect(await countAuthoredMalwares(author.internal_id)).toBe(MALWARES_COUNT);

    // A permanent delete is not capped
    await elDeleteElements(testContext, ADMIN_USER, [author], { forceDelete: true, maxSnapshotRelations: 3 });
    expect(await findLive(author.internal_id)).toHaveLength(0);
    expect(await countAuthoredMalwares(author.internal_id)).toBe(0);

    // Cleanup
    const liveMalwares = await elFindByIds(testContext, ADMIN_USER, malwares.map((m) => m.internal_id), { indices: READ_DATA_INDICES }) as BasicStoreBase[];
    await elDeleteElements(testContext, ADMIN_USER, liveMalwares);
  });

  it('should not write anything once the lock is lost', async () => {
    const { author, malwares } = await createAuthorWithRelations('Lock lost author');
    const controller = new AbortController();
    controller.abort();

    await expect(elDeleteElements(testContext, ADMIN_USER, [author], { batchSize: 2, signal: controller.signal })).rejects.toThrow();

    expect(await findLive(author.internal_id)).toHaveLength(1);
    expect(await countConnectedRelations(author.internal_id)).toBe(MALWARES_COUNT + 2);
    expect(await countAuthoredMalwares(author.internal_id)).toBe(MALWARES_COUNT);

    // Cleanup
    const liveMalwares = await elFindByIds(testContext, ADMIN_USER, malwares.map((m) => m.internal_id), { indices: READ_DATA_INDICES }) as BasicStoreBase[];
    await elDeleteElements(testContext, ADMIN_USER, [author, ...liveMalwares]);
  });

  it('should refuse a draft delete above the snapshot cap, before anything is copied to the draft', async () => {
    const { author, malwares } = await createAuthorWithRelations('Draft capped author');
    const draftContext = { ...testContext, draft_context: 'draft-delete-cap-test' };

    const draftDelete = elMarkElementsAsDraftDelete(draftContext, ADMIN_USER, [author], { batchSize: 2, maxSnapshotRelations: 3 });
    await expect(draftDelete).rejects.toThrow('Cannot delete element in draft: too many related relations, delete it outside the draft');

    expect(await findLive(author.internal_id)).toHaveLength(1);
    expect(await countConnectedRelations(author.internal_id)).toBe(MALWARES_COUNT + 2);

    // Cleanup
    const liveMalwares = await elFindByIds(testContext, ADMIN_USER, malwares.map((m) => m.internal_id), { indices: READ_DATA_INDICES }) as BasicStoreBase[];
    await elDeleteElements(testContext, ADMIN_USER, [author, ...liveMalwares]);
  });
});
