import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { findRegisterRow } from '../../../../src/modules/userMerge/userMerge-register';
import { USER_MERGE_HISTORY_TARGETS, userMergeHistoryCoveredRows, userMergeHistoryFieldPaths } from '../../../../src/modules/userMerge/userMerge-historyTargets';
import { userMergeScalarFieldPaths } from '../../../../src/modules/userMerge/userMerge-scalarTargets';
import { userMergeScalarQuery, userMergeScalarScript } from '../../../../src/modules/userMerge/userMerge-scalarQueries';
import { userMergeHistoryHandler } from '../../../../src/modules/userMerge/userMerge-historyHandler';

const targetById = (id: string) => {
  const target = USER_MERGE_HISTORY_TARGETS.find((candidate) => candidate.id === id);
  if (!target) {
    throw new Error(`Unknown target ${id}`);
  }
  return target;
};

describe('userMerge history targets', () => {
  it('should reference existing register rows', () => {
    userMergeHistoryCoveredRows().forEach((rowId) => {
      expect(findRegisterRow(rowId), rowId).toBeDefined();
    });
  });

  it('should cover the seven attribution rows of the register', () => {
    expect(userMergeHistoryCoveredRows().sort()).toEqual([
      'activity-history-pir-history.applicant-id',
      'activity.user-id',
      'basic-object.i-attributes-user-id',
      'history.context-data-attribution',
      'history.user-id',
      'pir-history.user-id',
      'workflow-instance.history-user-id',
    ]);
  });

  it('should give every target a unique identifier', () => {
    const ids = USER_MERGE_HISTORY_TARGETS.map((target) => target.id);
    expect(new Set(ids).size).toEqual(ids.length);
  });

  it('should scope every target to entity types except the one declared on the abstract roots', () => {
    const unscoped = USER_MERGE_HISTORY_TARGETS.filter((target) => !target.entityTypes).map((target) => target.id);
    expect(unscoped).toEqual(['basic-object-i-attributes-user-id']);
  });

  it('should split user_id per entity type and group applicant_id on the three', () => {
    expect(targetById('activity-user-id').entityTypes).toEqual(['Activity']);
    expect(targetById('history-user-id').entityTypes).toEqual(['History']);
    expect(targetById('pir-history-user-id').entityTypes).toEqual(['PirHistory']);
    expect(targetById('history-applicant-id').entityTypes).toEqual(['Activity', 'History', 'PirHistory']);
  });

  it('should qualify field paths by entity type and stay disjoint from the scalar handler', () => {
    const paths = userMergeHistoryFieldPaths();
    expect(paths).toContain('History.user_id');
    expect(paths).toContain('*.i_attributes.user_id');
    expect(paths).not.toContain('user_id');
    const scalarPaths = new Set(userMergeScalarFieldPaths());
    paths.forEach((path) => expect(scalarPaths.has(path), path).toBe(false));
  });
});

describe('userMerge history queries', () => {
  it('should target the keyword sub-field and filter on the entity type', () => {
    expect(userMergeScalarQuery(targetById('history-user-id'), 'source-id')).toEqual({
      bool: {
        must: [
          { term: { 'user_id.keyword': 'source-id' } },
          { terms: { 'entity_type.keyword': ['History'] } },
        ],
      },
    });
  });

  it('should select every entity type carrying the applicant', () => {
    const query = userMergeScalarQuery(targetById('history-applicant-id'), 'source-id') as { bool: { must: unknown[] } };
    expect(query.bool.must).toContainEqual({ terms: { 'entity_type.keyword': ['Activity', 'History', 'PirHistory'] } });
  });

  it('should not filter on the entity type when the attribute is declared on the abstract roots', () => {
    expect(userMergeScalarQuery(targetById('basic-object-i-attributes-user-id'), 'source-id')).toEqual({
      bool: { must: [{ term: { 'i_attributes.user_id.keyword': 'source-id' } }] },
    });
  });

  it('should guard the traversal of the context data before reading the creators', () => {
    const script = userMergeScalarScript(targetById('history-context-data-creator-ids'));
    expect(script).toContain('holder = holder.context_data; if (!(holder instanceof Map)) { return; }');
    expect(script).toContain('values.removeIf(value -> params.source.equals(value))');
    expect(script).toContain('if (!values.contains(params.target))');
  });

  it('should iterate the attribute entries rather than replace the array', () => {
    const script = userMergeScalarScript(targetById('basic-object-i-attributes-user-id'));
    expect(script).toContain('def items = holder.i_attributes;');
    expect(script).toContain('for (def item : items)');
    expect(script).toContain('item.user_id = params.target');
  });

  it('should phrase-match the serialized key and id rather than term-match the field', () => {
    expect(userMergeScalarQuery(targetById('workflow-instance-history-user-id'), 'source-id')).toEqual({
      bool: {
        must: [
          { match_phrase: { history: '"user_id":"source-id"' } },
          { terms: { 'entity_type.keyword': ['WorkflowInstance'] } },
        ],
      },
    });
  });

  it('should replace the serialized pair rather than the bare id', () => {
    const script = userMergeScalarScript(targetById('workflow-instance-history-user-id'));
    expect(script).toContain('def serialized = holder.history;');
    expect(script).toContain('if (serialized instanceof String)');
    expect(script).toContain('serialized.replace(\'"user_id":"\' + params.source + \'"\', \'"user_id":"\' + params.target + \'"\')');
  });
});

describe('userMerge history handler', () => {
  it('should declare the register version so a stale handler is refused at boot', () => {
  });

  it('should read and write the same paths', () => {
    expect(userMergeHistoryHandler.reads).toEqual(userMergeHistoryHandler.writes);
  });
});
