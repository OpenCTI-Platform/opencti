import { describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/database/cache', () => ({ getEntityFromCache: vi.fn() }));
vi.mock('../../../src/database/stream/stream-handler', () => ({ storeActivityEvent: vi.fn() }));

import { ACTIVITY_MAX_STRING_LENGTH, ACTIVITY_TRUNCATED_MARKER, cleanInputData } from '../../../src/manager/activityListener';

// Elasticsearch rejects a flattened value whose key and value are longer than 32766 bytes
const ELASTIC_MAX_TERM_BYTES = 32766;

describe('Activity listener: cleanInputData', () => {
  it('keeps short strings as they are', () => {
    const data = { id: 'workspace-id', input: [{ key: 'name', value: ['New name'] }] };
    expect(cleanInputData(data)).toEqual(data);
  });

  it('keeps a string of exactly the maximum length', () => {
    const value = 'a'.repeat(ACTIVITY_MAX_STRING_LENGTH);
    expect(cleanInputData({ input: { description: value } }).input.description).toEqual(value);
  });

  it('truncates a long string inside an edit input value', () => {
    const graphData = 'A'.repeat(72000);
    const cleaned = cleanInputData({ id: 'workspace-id', input: [{ key: 'graph_data', value: [graphData] }] });
    const [truncated] = cleaned.input[0].value;
    expect(truncated).toEqual(`${'A'.repeat(ACTIVITY_MAX_STRING_LENGTH)}${ACTIVITY_TRUNCATED_MARKER}`);
    expect(cleaned.input[0].key).toEqual('graph_data');
  });

  it('truncates long strings at any depth and outside of the input', () => {
    const long = 'b'.repeat(ACTIVITY_MAX_STRING_LENGTH + 1);
    const cleaned = cleanInputData({ entity_name: long, input: { nested: { deeper: [{ content: long }] } } });
    expect(cleaned.entity_name.endsWith(ACTIVITY_TRUNCATED_MARKER)).toBe(true);
    expect(cleaned.input.nested.deeper[0].content.endsWith(ACTIVITY_TRUNCATED_MARKER)).toBe(true);
  });

  it('keeps a truncated multi-byte value under the indexing limit', () => {
    const cleaned = cleanInputData({ input: { description: '€'.repeat(20000) } });
    expect(Buffer.byteLength(`description${cleaned.input.description}`, 'utf8')).toBeLessThan(ELASTIC_MAX_TERM_BYTES);
  });

  it('never cuts a surrogate pair in half', () => {
    // Shift by one character so that a pair straddles the maximum length
    const value = `x${'\u{1F600}'.repeat(ACTIVITY_MAX_STRING_LENGTH)}`;
    const truncated = cleanInputData({ input: { description: value } }).input.description as string;
    const kept = truncated.slice(0, -ACTIVITY_TRUNCATED_MARKER.length);
    expect(kept.length).toEqual(ACTIVITY_MAX_STRING_LENGTH - 1);
    expect(kept).toEqual(`x${'\u{1F600}'.repeat((ACTIVITY_MAX_STRING_LENGTH - 2) / 2)}`);
  });

  it('does not modify the original data', () => {
    const long = 'c'.repeat(ACTIVITY_MAX_STRING_LENGTH * 2);
    const data = { input: [{ key: 'description', value: [long] }] };
    cleanInputData(data);
    expect(data.input[0].value[0]).toEqual(long);
  });

  it('still redacts sensitive values and removes unsupported input props', () => {
    const cleaned = cleanInputData({ input: { password: 'secret-value', _id: 'internal', sort: 'name', name: 'kept' } });
    expect(cleaned.input.password).not.toEqual('secret-value');
    expect(cleaned.input._id).toBeUndefined();
    expect(cleaned.input.sort).toBeUndefined();
    expect(cleaned.input.name).toEqual('kept');
  });
});
