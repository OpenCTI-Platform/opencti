import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { findRegisterRow } from '../../../../src/modules/userMerge/userMerge-register';
import { userMergeScalarCoveredRows, userMergeScalarFieldPaths, userMergeScalarTargets } from '../../../../src/modules/userMerge/userMerge-scalarTargets';
import { userMergeScalarQuery, userMergeScalarScript, userMergeScalarUpdateBody } from '../../../../src/modules/userMerge/userMerge-scalarQueries';

const targetById = (id: string) => {
  const target = userMergeScalarTargets().find((candidate) => candidate.id === id);
  if (!target) {
    throw new Error(`Unknown target ${id}`);
  }
  return target;
};

describe('userMerge scalar targets', () => {
  it('should reference existing register rows', () => {
    userMergeScalarCoveredRows().forEach((rowId) => {
      expect(findRegisterRow(rowId), rowId).toBeDefined();
    });
  });

  it('should give every target a unique identifier', () => {
    const ids = userMergeScalarTargets().map((target) => target.id);
    expect(new Set(ids).size).toEqual(ids.length);
  });

  it('should scope every target to entity types except the genuinely global one', () => {
    const unscoped = userMergeScalarTargets().filter((target) => !target.entityTypes).map((target) => target.id);
    expect(unscoped).toEqual(['basic-object-creator-id']);
  });

  it('should group the entities sharing a register row into a single target', () => {
    expect(targetById('ingestion-user-id').entityTypes).toHaveLength(5);
  });

  it('should read the cardinality from the schema rather than from a declaration', () => {
    expect(targetById('basic-object-creator-id').shape).toEqual('multiple');
    expect(targetById('sync-user-id').shape).toEqual('single');
  });

  it('should qualify field paths by entity type so two chunks sharing a field name stay disjoint', () => {
    const paths = userMergeScalarFieldPaths();
    expect(paths).toContain('Sync.user_id');
    expect(paths).toContain('*.creator_id');
    expect(paths).not.toContain('user_id');
  });

  it('should split each lifecycle pair into the two register rows it answers for', () => {
    expect(targetById('work-terminal-user-id').condition).toEqual({ path: 'status', equals: 'complete' });
    expect(targetById('work-active-user-id').condition).toEqual({ path: 'status', equals: 'complete', negate: true });
    expect(targetById('work-active-user-id').registerRow).not.toEqual(targetById('work-terminal-user-id').registerRow);
  });
});

describe('userMerge scalar queries', () => {
  it('should target the keyword sub-field of a text mapping', () => {
    const query = userMergeScalarQuery(targetById('sync-user-id'), 'source-id') as never;
    expect(query).toEqual({
      bool: {
        must: [
          { term: { 'user_id.keyword': 'source-id' } },
          { terms: { 'entity_type.keyword': ['Sync'] } },
        ],
      },
    });
  });

  it('should keep a boolean condition on the bare path', () => {
    const query = userMergeScalarQuery(targetById('notification-read-user-id'), 'source-id') as { bool: { must: unknown[] } };
    expect(query.bool.must).toContainEqual({ term: { is_read: true } });
  });

  it('should push a negated condition to must_not so documents missing the field are selected', () => {
    const query = userMergeScalarQuery(targetById('background-task-pending-initiator-id'), 'source-id') as {
      bool: { must: unknown[]; must_not: unknown[] };
    };
    expect(query.bool.must_not).toEqual([{ term: { completed: true } }]);
    expect(query.bool.must).not.toContainEqual({ term: { completed: true } });
  });

  it('should wrap a nested path in a nested query', () => {
    const query = userMergeScalarQuery(targetById('workflow-definition-all-versions-created-by'), 'source-id') as {
      bool: { must: unknown[] };
    };
    expect(query.bool.must[0]).toEqual({
      nested: { path: 'all_versions', query: { term: { 'all_versions.createdBy.keyword': 'source-id' } } },
    });
  });

  it('should remove before appending on a multiple field so a replay is a no-op', () => {
    const script = userMergeScalarScript(targetById('basic-object-creator-id'));
    expect(script).toContain('values.removeIf(value -> params.source.equals(value))');
    expect(script).toContain('if (!values.contains(params.target))');
  });

  it('should guard the traversal of a nested single path', () => {
    const script = userMergeScalarScript(targetById('internal-file-metadata-creator-id'));
    expect(script).toContain('holder = holder.metaData; if (!(holder instanceof Map)) { return; }');
    expect(script).toContain('holder.creator_id = params.target');
  });

  it('should iterate the items of an object array', () => {
    const script = userMergeScalarScript(targetById('workflow-definition-all-versions-created-by'));
    expect(script).toContain('for (def item : items)');
    expect(script).toContain('item.createdBy = params.target');
  });

  it('should apply on the very query the count was taken from', () => {
    const target = targetById('work-terminal-user-id');
    const body = userMergeScalarUpdateBody(target, 'source-id', 'target-id') as { query: unknown; script: { params: unknown } };
    expect(body.query).toEqual(userMergeScalarQuery(target, 'source-id'));
    expect(body.script.params).toEqual({ source: 'source-id', target: 'target-id' });
  });
});
