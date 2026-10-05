import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { findRegisterRow } from '../../../../src/modules/userMerge/userMerge-register';
import { userMergeScalarTargets } from '../../../../src/modules/userMerge/userMerge-scalarTargets';
import { userMergeScalarQuery, userMergeScalarScript } from '../../../../src/modules/userMerge/userMerge-scalarQueries';
import { ENTITY_TYPE_SOURCE, ENTITY_TYPE_SOURCE_RECOMMENDATION } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-types';

const targetById = (id: string) => {
  const target = userMergeScalarTargets().find((candidate) => candidate.id === id);
  if (!target) {
    throw new Error(`Unknown target ${id}`);
  }
  return target;
};

describe('userMerge source intelligence targets', () => {
  it('should transfer the user of an analyst source, and only of an analyst source', () => {
    const target = targetById('source-analyst-ref-id');
    expect(findRegisterRow(target.registerRow)).toBeDefined();
    expect(userMergeScalarQuery(target, 'source-id')).toEqual({
      bool: {
        must: [
          { term: { 'ref_id.keyword': 'source-id' } },
          { terms: { 'entity_type.keyword': [ENTITY_TYPE_SOURCE] } },
          { term: { 'source_kind.keyword': 'manual' } },
        ],
      },
    });
    expect(userMergeScalarScript(target)).toContain('if (params.source.equals(holder.ref_id)) { holder.ref_id = params.target; }');
  });

  it('should transfer the users stored in the payload and the revert payload of a recommendation', () => {
    ['source-recommendation-payload-user-id', 'source-recommendation-revert-payload-user-id'].forEach((id) => {
      const target = targetById(id);
      expect(findRegisterRow(target.registerRow)).toBeDefined();
      expect(userMergeScalarQuery(target, 'source-id')).toEqual({
        bool: {
          must: [
            { match_phrase: { [target.path]: '"user_id":"source-id"' } },
            { terms: { 'entity_type.keyword': [ENTITY_TYPE_SOURCE_RECOMMENDATION] } },
          ],
        },
      });
      expect(userMergeScalarScript(target)).toContain(`def serialized = holder.${target.path};`);
    });
  });

  it('should match how recommendation payloads are serialized', () => {
    // Payloads are stored with JSON.stringify, without spaces around the separator
    expect(JSON.stringify({ target: 'user', user_id: 'source-id', proposed_max_confidence: 40 })).toContain('"user_id":"source-id"');
  });
});
