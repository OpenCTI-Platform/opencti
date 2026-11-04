import { describe, expect, it, vi } from 'vitest';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { stixObjectOrRelationshipAddRefRelation } from '../../../src/domain/stixObjectOrStixRelationship';
import { elLoadById } from '../../../src/database/engine';
import { storeLoadByIdWithRefs } from '../../../src/database/middleware';
import { MISSING_REF_ERROR } from '../../../src/config/errors';
import { RELATION_OBJECT_LABEL } from '../../../src/schema/stixRefRelationship';
import { ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';

// Keep the real modules, only stub the target loading and spy on the source loading
vi.mock('../../../src/database/engine', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/database/engine')>();
  return { ...actual, elLoadById: vi.fn() };
});
vi.mock('../../../src/database/middleware', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/database/middleware')>();
  return { ...actual, storeLoadByIdWithRefs: vi.fn() };
});

describe('stixObjectOrRelationshipAddRefRelation', () => {
  it('should reject the ref relation when its target cannot be found', async () => {
    // elLoadById is typed Promise<T> but resolves undefined when the element is not found
    vi.mocked(elLoadById).mockResolvedValueOnce(undefined as unknown as Awaited<ReturnType<typeof elLoadById>>);
    const input = { relationship_type: RELATION_OBJECT_LABEL, toId: 'unknown-id' };
    await expect(() => stixObjectOrRelationshipAddRefRelation(testContext, ADMIN_USER, 'malware-id', input, ENTITY_TYPE_MALWARE))
      .rejects.toMatchObject({
        message: 'Element(s) not found',
        extensions: { code: MISSING_REF_ERROR, data: { input: { toId: 'unknown-id' }, doc_code: 'ELEMENT_NOT_FOUND' } },
      });
    // The source is not patched
    expect(storeLoadByIdWithRefs).not.toHaveBeenCalled();
  });
});
