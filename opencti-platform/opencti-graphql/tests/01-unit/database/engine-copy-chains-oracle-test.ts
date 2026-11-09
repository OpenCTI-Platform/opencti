import { describe, expect, it } from 'vitest';
import * as R from 'ramda';
import '../../../src/modules/index';
import { bulkIndexDocument, prepareRelation } from '../../../src/database/engine';
import { DatabaseError } from '../../../src/config/errors';
import { extractEntityRepresentativeName } from '../../../src/database/entity-representative';
import { getParentTypes } from '../../../src/schema/schemaUtils';
import { INTERNAL_FROM_FIELD, INTERNAL_TO_FIELD } from '../../../src/schema/identifier';

// region reference: prepareRelation and the bulk body before the copy chain rewrite (@b48f3c0250)
const prepareRelationReference = (thing: Record<string, any>) => {
  if (thing.fromRole === undefined || thing.toRole === undefined) {
    throw DatabaseError('Cant index relation connections without from or to', {
      id: thing.internal_id,
      fromId: thing.fromId,
      toId: thing.toId,
    });
  }
  const connections = [];
  if (!thing.from || !thing.to) {
    throw DatabaseError('Cant index relation, error resolving dependency IDs', {
      id: thing.internal_id,
      fromId: thing.fromId,
      toId: thing.toId,
    });
  }
  const { from, to } = thing;

  if (!from.entity_type || !to.entity_type) {
    throw DatabaseError('Cant index relation, error resolving from or to entity type', {
      id: thing.internal_id,
      fromId: thing.fromId,
      toId: thing.toId,
      fromResolved: from,
      toResolved: to,
    });
  }

  connections.push({
    internal_id: from.internal_id,
    name: extractEntityRepresentativeName(from),
    types: [from.entity_type, ...getParentTypes(from.entity_type)],
    role: thing.fromRole,
  });
  connections.push({
    internal_id: to.internal_id,
    name: extractEntityRepresentativeName(to),
    types: [to.entity_type, ...getParentTypes(to.entity_type)],
    role: thing.toRole,
  });
  return R.pipe(
    R.assoc('connections', connections),
    R.dissoc(INTERNAL_TO_FIELD),
    R.dissoc(INTERNAL_FROM_FIELD),
    // Dissoc from
    R.dissoc('from'),
    R.dissoc('fromId'),
    R.dissoc('fromRole'),
    R.dissoc('fromType'),
    // Dissoc to
    R.dissoc('to'),
    R.dissoc('toId'),
    R.dissoc('toRole'),
    R.dissoc('toType'),
  )(thing);
};
const bulkIndexDocumentReference = (doc: Record<string, any>) => R.pipe(R.dissoc('_index'))(doc);
// endregion

const entity = (entityType: string, name: string) => ({
  internal_id: `${name}-id`,
  standard_id: `${entityType.toLowerCase()}--${name}`,
  entity_type: entityType,
  name,
  parent_types: getParentTypes(entityType),
});
const relation = (index: number): Record<string, any> => {
  const from = entity('Report', `report-${index}`);
  const to = index % 2 === 0 ? entity('Malware', `malware-${index}`) : entity('Indicator', `indicator-${index}`);
  return {
    _index: 'opencti_stix_meta_relationships',
    id: `rel-${index}`,
    from,
    fromId: from.internal_id,
    fromRole: 'object_from',
    fromType: from.entity_type,
    to,
    toId: to.internal_id,
    toRole: 'object_to',
    toType: to.entity_type,
    base_type: 'RELATION',
    parent_types: ['basic-relationship', 'stix-relationship', 'stix-ref-relationship'],
    internal_id: `rel-${index}`,
    standard_id: `relationship-meta--${index}`,
    entity_type: 'object',
    relationship_type: 'object',
    created_at: '2024-01-01T00:00:00.000Z',
    start_time: new Date(0),
    i_inference_weight: undefined,
    [INTERNAL_FROM_FIELD]: index % 3 === 0 ? ['x'] : undefined,
  };
};
const buildThings = (): [string, () => Record<string, any>][] => {
  const things: [string, () => Record<string, any>][] = [];
  for (let index = 0; index < 20; index += 1) {
    things.push([`relation ${index}`, () => relation(index)]);
  }
  things.push(['existing connections key', () => ({ connections: ['old'], ...relation(1) })]);
  things.push(['existing connections key in the middle', () => ({ ...relation(2), connections: ['old'], last: 1 })]);
  things.push(['to fields first', () => {
    const r = relation(3);
    return { toType: r.toType, toRole: r.toRole, toId: r.toId, to: r.to, ...r, [INTERNAL_TO_FIELD]: ['y'] };
  }]);
  things.push(['integer like keys', () => ({ 2: 'two', ...relation(4), 1: 'one' })]);
  things.push(['inherited enumerable', () => Object.assign(Object.create({ inherited: 1, connections: 'inherited', fromId: 'hidden' }), relation(5))]);
  things.push(['own __proto__', () => Object.assign(JSON.parse('{"__proto__":{"polluted":1,"toId":"p"},"a":1}'), relation(6))]);
  things.push(['nested own __proto__', () => Object.assign(JSON.parse('{"__proto__":{"b":2,"__proto__":{"c":3}},"a":1}'), relation(7))]);
  things.push(['null own __proto__', () => Object.assign(JSON.parse('{"__proto__":null}'), relation(8))]);
  things.push(['missing fromRole', () => R.dissoc('fromRole', relation(9))]);
  things.push(['missing to', () => R.dissoc('to', relation(10))]);
  things.push(['to without entity type', () => ({ ...relation(11), to: { internal_id: 'x' } })]);
  return things;
};

const outcome = (fn: () => any) => {
  try {
    return { value: fn() };
  } catch (err: any) {
    return { error: `${err.name}: ${err.message}` };
  }
};
const EXPECTED_ERRORS = ['missing fromRole', 'missing to', 'to without entity type'];
const expectSameDocument = (actual: any, expected: any, label: string) => {
  expect(actual.error === undefined, `${label}: ${actual.error}`).toBe(!EXPECTED_ERRORS.includes(label));
  expect(actual, label).toStrictEqual(expected);
  expect(JSON.stringify(actual), label).toBe(JSON.stringify(expected));
  if (expected.value) {
    expect(Object.keys(actual.value), label).toStrictEqual(Object.keys(expected.value));
    expect(Object.getPrototypeOf(actual.value), label).toStrictEqual(Object.getPrototypeOf(expected.value));
  }
};

describe('indexing copy chains equivalence with ramda', () => {
  it.each(buildThings())('should prepare the same relation document: %s', (label, factory) => {
    expectSameDocument(outcome(() => prepareRelation(factory())), outcome(() => prepareRelationReference(factory())), label);
  });

  it.each(buildThings().filter(([label]) => !EXPECTED_ERRORS.includes(label)))('should build the same bulk body: %s', (label, factory) => {
    expectSameDocument(outcome(() => bulkIndexDocument(factory())), outcome(() => bulkIndexDocumentReference(factory())), label);
  });
});
