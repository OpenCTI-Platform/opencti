import type { UserMergeScalarTarget } from './userMerge-scalarTargets';

/**
 * Elasticsearch term key for a path.
 *
 * `format: 'id'` and `format: 'short'` both map to `text` with a `keyword` sub-field, so a
 * term query on the bare path never matches. Booleans map to `boolean` and must stay bare.
 */
const termKey = (path: string, value: string | boolean): string => {
  return typeof value === 'boolean' ? path : `${path}.keyword`;
};

const conditionClause = (target: UserMergeScalarTarget): Record<string, unknown> | undefined => {
  if (!target.condition) {
    return undefined;
  }
  const { path, equals } = target.condition;
  return { term: { [termKey(path, equals)]: equals } };
};

/**
 * Query selecting the documents this target has to rewrite.
 *
 * A negated condition goes to `must_not`, which also selects documents where the field is
 * absent — an unfinished work has no `status` yet and is still an active work.
 */
export const userMergeScalarQuery = (target: UserMergeScalarTarget, sourceId: string): Record<string, unknown> => {
  const valueClause = { term: { [termKey(target.path, sourceId)]: sourceId } };
  const must: Record<string, unknown>[] = [
    target.nestedRoot ? { nested: { path: target.nestedRoot, query: valueClause } } : valueClause,
  ];
  const mustNot: Record<string, unknown>[] = [];
  if (target.entityTypes) {
    must.push({ terms: { 'entity_type.keyword': target.entityTypes } });
  }
  const condition = conditionClause(target);
  if (condition) {
    if (target.condition?.negate) {
      mustNot.push(condition);
    } else {
      must.push(condition);
    }
  }
  return { bool: mustNot.length > 0 ? { must, must_not: mustNot } : { must } };
};

const traversalPrelude = (segments: string[]): string => {
  return segments
    .map((segment) => `holder = holder.${segment}; if (!(holder instanceof Map)) { return; }`)
    .join(' ');
};

const singleScript = (path: string): string => {
  const segments = path.split('.');
  const leaf = segments.pop() as string;
  const prelude = segments.length > 0 ? `${traversalPrelude(segments)} ` : '';
  return `def holder = ctx._source; ${prelude}if (params.source.equals(holder.${leaf})) { holder.${leaf} = params.target; }`;
};

/**
 * Removal then guarded append rather than a replacement in place: this is what makes a
 * replay a no-op on a `multiple:true` field instead of a second append.
 */
const multipleScript = (path: string): string => {
  const segments = path.split('.');
  const leaf = segments.pop() as string;
  const prelude = segments.length > 0 ? `${traversalPrelude(segments)} ` : '';
  return `def holder = ctx._source; ${prelude}def values = holder.${leaf};`
    + ' if (values instanceof List) { values.removeIf(value -> params.source.equals(value));'
    + ' if (!values.contains(params.target)) { values.add(params.target); } }';
};

const objectArrayScript = (path: string): string => {
  const segments = path.split('.');
  const leaf = segments.pop() as string;
  const root = segments.pop() as string;
  const prelude = segments.length > 0 ? `${traversalPrelude(segments)} ` : '';
  return `def holder = ctx._source; ${prelude}def items = holder.${root};`
    + ' if (items instanceof List) { for (def item : items) {'
    + ` if (item instanceof Map && params.source.equals(item.${leaf})) { item.${leaf} = params.target; } } }`;
};

export const userMergeScalarScript = (target: UserMergeScalarTarget): string => {
  if (target.shape === 'multiple') {
    return multipleScript(target.path);
  }
  if (target.shape === 'object-array') {
    return objectArrayScript(target.path);
  }
  return singleScript(target.path);
};

/** Body for `_update_by_query`, paired with the very query the plan was counted from. */
export const userMergeScalarUpdateBody = (
  target: UserMergeScalarTarget,
  sourceId: string,
  targetId: string,
): Record<string, unknown> => {
  return {
    query: userMergeScalarQuery(target, sourceId),
    script: {
      source: userMergeScalarScript(target),
      lang: 'painless',
      params: { source: sourceId, target: targetId },
    },
  };
};
