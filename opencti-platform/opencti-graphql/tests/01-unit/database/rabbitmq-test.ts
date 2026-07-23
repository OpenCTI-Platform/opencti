import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mockHttpClient = {
  get: vi.fn(),
  delete: vi.fn(),
};

vi.mock('../../../src/utils/http-client', () => ({
  getHttpClient: vi.fn(() => mockHttpClient),
}));

vi.mock('../../../src/config/conf', () => ({
  default: { get: vi.fn(() => undefined) },
  booleanConf: vi.fn(() => false),
  configureCA: vi.fn(() => ({})),
  loadCert: vi.fn(),
  logApp: {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
  },
}));

vi.mock('../../../src/config/tracing', () => ({
  telemetry: vi.fn((_ctx: unknown, _user: unknown, _name: unknown, _attrs: unknown, fn: () => unknown) => fn()),
}));

vi.mock('../../../src/database/utils', () => ({
  isEmptyField: vi.fn((v: unknown) => !v),
  RABBIT_QUEUE_PREFIX: 'opencti_',
  wait: vi.fn(),
  toBase64: vi.fn((v: string | null | undefined) => (v ? Buffer.from(v, 'utf-8').toString('base64') : undefined)),
  fromBase64: vi.fn((v: string | null | undefined) => (v ? Buffer.from(v, 'base64').toString('utf-8') : undefined)),
}));

vi.mock('../../../src/domain/work', () => ({
  updateExpectationsNumber: vi.fn(),
}));

vi.mock('../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(async () => []),
}));

vi.mock('../../../src/database/raw-file-storage', () => ({
  s3ConnectionConfig: vi.fn(() => ({})),
}));

vi.mock('../../../src/utils/access', () => ({
  SYSTEM_USER: {},
}));

vi.mock('../../../src/schema/internalObject', () => ({
  ENTITY_TYPE_BACKGROUND_TASK: 'Background-Task',
  ENTITY_TYPE_CONNECTOR: 'Connector',
  ENTITY_TYPE_SYNC: 'Sync',
}));

vi.mock('../../../src/modules/playbook/playbook-types', () => ({
  ENTITY_TYPE_PLAYBOOK: 'Playbook',
}));

// Mock LRUCache so the cache never returns stale data between test
vi.mock('lru-cache', () => {
  class FakeLRUCache {
    get() {
      return undefined;
    }

    set() { /* no-op */ }
  }
  return { LRUCache: FakeLRUCache };
});

import { buildSplitMessages, getConnectorQueueSize, metrics } from '../../../src/database/rabbitmq';

describe('rabbitmq: metrics', () => {
  const context = {};
  const user = {};

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return overview, consumers count and filtered platform queues', async () => {
    const overviewData = { rabbitmq_version: '3.12.0', cluster_name: 'test' };
    mockHttpClient.get.mockImplementation((url: string) => {
      if (url === '/api/overview') {
        return Promise.resolve({ data: overviewData });
      }
      if (url.includes('/api/queues')) {
        return Promise.resolve({
          data: [
            { name: 'opencti_push_connector-abc', messages: 42, consumers: 3 },
            { name: 'opencti_listen_connector-abc', messages: 5, consumers: 0 },
            { name: 'other_queue', messages: 100, consumers: 2 },
          ],
        });
      }
      return Promise.resolve({ data: {} });
    });

    const result = await metrics(context, user);

    expect(result.overview).toEqual(overviewData);
    expect(result.consumers).toBe(3);
    // Only platform queues (starting with 'opencti_') should be included
    expect(result.queues).toHaveLength(2);
    expect(result.queues.every((q: { name: string }) => q.name.startsWith('opencti_'))).toBe(true);
  });

  it('should return consumers as 0 when no push queues have consumers', async () => {
    mockHttpClient.get.mockImplementation((url: string) => {
      if (url === '/api/overview') {
        return Promise.resolve({ data: { rabbitmq_version: '3.12.0' } });
      }
      if (url.includes('/api/queues')) {
        return Promise.resolve({
          data: [
            { name: 'opencti_push_connector-abc', messages: 10, consumers: 0 },
            { name: 'opencti_listen_connector-abc', messages: 5, consumers: 0 },
          ],
        });
      }
      return Promise.resolve({ data: {} });
    });

    const result = await metrics(context, user);

    expect(result.consumers).toBe(0);
  });

  it('should return empty queues when no platform queues exist', async () => {
    mockHttpClient.get.mockImplementation((url: string) => {
      if (url === '/api/overview') {
        return Promise.resolve({ data: { rabbitmq_version: '3.12.0' } });
      }
      if (url.includes('/api/queues')) {
        return Promise.resolve({
          data: [
            { name: 'some_other_queue', messages: 100, consumers: 5 },
          ],
        });
      }
      return Promise.resolve({ data: {} });
    });

    const result = await metrics(context, user);

    expect(result.overview).toEqual({ rabbitmq_version: '3.12.0' });
    expect(result.consumers).toBe(0);
    expect(result.queues).toHaveLength(0);
  });

  it('should pass a 5 seconds timeout to the GET requests', async () => {
    mockHttpClient.get.mockImplementation(() => {
      return Promise.resolve({ data: [] });
    });

    await metrics(context, user);

    expect(mockHttpClient.get).toHaveBeenCalledTimes(2);
    expect(mockHttpClient.get).toHaveBeenCalledWith('/api/overview', { timeout: 5000 });
    expect(mockHttpClient.get).toHaveBeenCalledWith(expect.stringContaining('/api/queues'), { timeout: 5000 });
  });

  it('should propagate errors from the HTTP client', async () => {
    mockHttpClient.get.mockRejectedValue(new Error('Connection refused'));

    await expect(metrics(context, user)).rejects.toThrow('Connection refused');
  });
});

describe('rabbitmq: getConnectorQueueSize', () => {
  const context = {};
  const user = {};

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return the message count when exactly one queue matches', async () => {
    mockHttpClient.get.mockImplementation((url: string) => {
      if (url === '/api/overview') {
        return Promise.resolve({ data: { rabbitmq_version: '3.12.0' } });
      }
      if (url.includes('/api/queues')) {
        return Promise.resolve({
          data: [
            { name: 'opencti_push_connector-abc', messages: 42, consumers: 1 },
            { name: 'opencti_push_connector-xyz', messages: 10, consumers: 1 },
          ],
        });
      }
      return Promise.resolve({ data: {} });
    });

    const result = await getConnectorQueueSize(context, user, 'connector-abc');
    expect(result).toBe(42);
  });

  it('should return 0 when exactly one queue matches but messages is undefined', async () => {
    mockHttpClient.get.mockImplementation((url: string) => {
      if (url === '/api/overview') {
        return Promise.resolve({ data: { rabbitmq_version: '3.12.0' } });
      }
      if (url.includes('/api/queues')) {
        return Promise.resolve({
          data: [
            { name: 'opencti_push_connector-abc', consumers: 1 },
          ],
        });
      }
      return Promise.resolve({ data: {} });
    });

    const result = await getConnectorQueueSize(context, user, 'connector-abc');
    expect(result).toBe(0);
  });

  it('should return 0 when no queues match', async () => {
    mockHttpClient.get.mockImplementation((url: string) => {
      if (url === '/api/overview') {
        return Promise.resolve({ data: { rabbitmq_version: '3.12.0' } });
      }
      if (url.includes('/api/queues')) {
        return Promise.resolve({
          data: [
            { name: 'opencti_push_connector-xyz', messages: 10, consumers: 1 },
          ],
        });
      }
      return Promise.resolve({ data: {} });
    });

    const result = await getConnectorQueueSize(context, user, 'connector-unknown');
    expect(result).toBe(0);
  });

  it('should return the sum of messages when multiple queues match', async () => {
    mockHttpClient.get.mockImplementation((url: string) => {
      if (url === '/api/overview') {
        return Promise.resolve({ data: { rabbitmq_version: '3.12.0' } });
      }
      if (url.includes('/api/queues')) {
        return Promise.resolve({
          data: [
            { name: 'opencti_push_connector-abc', messages: 10, consumers: 1 },
            { name: 'opencti_listen_connector-abc', messages: 5, consumers: 0 },
          ],
        });
      }
      return Promise.resolve({ data: {} });
    });

    const result = await getConnectorQueueSize(context, user, 'connector-abc');
    expect(result).toBe(15);
  });
});

describe('rabbitmq: buildSplitMessages (Proposal B - Node.js bundle splitting)', () => {
  const toBundle = (objects: unknown[]) => Buffer.from(JSON.stringify({ id: 'bundle--test', type: 'bundle', objects }), 'utf-8').toString('base64');
  const decode = (base64Content: string) => JSON.parse(Buffer.from(base64Content, 'base64').toString('utf-8'));

  it('returns null for non-bundle messages', () => {
    const message = { type: 'event', content: 'irrelevant' };
    expect(buildSplitMessages(message)).toBeNull();
  });

  it('returns null for messages explicitly marked no_split', () => {
    const message = {
      type: 'bundle',
      no_split: true,
      content: toBundle([{ id: 'malware--a', type: 'malware' }, { id: 'malware--b', type: 'malware' }]),
    };
    expect(buildSplitMessages(message)).toBeNull();
  });

  it('returns null for single-object bundles', () => {
    const message = { type: 'bundle', content: toBundle([{ id: 'malware--only', type: 'malware', name: 'Only' }]) };
    expect(buildSplitMessages(message)).toBeNull();
  });

  it('returns null for a single-object bundle even when the object has no id (malformed/partial STIX)', () => {
    // Regression test: a real TAXII response can contain an object with no `id` field.
    // The splitter's dependency walk cannot safely handle that, so single-object bundles
    // must be short-circuited before ever invoking it - mirroring the worker's own
    // `len(content['objects']) == 1` pre-check in push_handler.py.
    const message = { type: 'bundle', content: toBundle([{ type: 'report', confidence: 100 }]) };
    expect(buildSplitMessages(message)).toBeNull();
  });

  it('splits a multi-object bundle into one message per object, preserving other fields', () => {
    const objects = [
      { id: 'marking-definition--m1', type: 'marking-definition', definition_type: 'tlp', name: 'TLP:RED' },
      { id: 'malware--m', type: 'malware', name: 'Mal', object_marking_refs: ['marking-definition--m1'] },
      { id: 'indicator--i', type: 'indicator', name: 'Ind', pattern: "[file:hashes.MD5 = 'x']", object_marking_refs: ['marking-definition--m1'] },
      { id: 'relationship--r', type: 'relationship', relationship_type: 'based-on', source_ref: 'indicator--i', target_ref: 'malware--m' },
    ];
    const message = { type: 'bundle', content: toBundle(objects), work_id: 'work-1', applicant_id: 'user-1', update: true };

    const splitMessages = buildSplitMessages(message);

    expect(splitMessages).not.toBeNull();
    expect(splitMessages).toHaveLength(objects.length);
    const ids = (splitMessages as { content: string; no_split: boolean; work_id: string; applicant_id: string; update: boolean }[]).map((msg) => {
      expect(msg.no_split).toBe(true);
      expect(msg.work_id).toBe('work-1');
      expect(msg.applicant_id).toBe('user-1');
      expect(msg.update).toBe(true);
      const decoded = decode(msg.content);
      expect(decoded.objects).toHaveLength(1);
      return decoded.objects[0].id;
    });
    expect(new Set(ids)).toEqual(new Set(objects.map((o) => o.id)));
  });

  it('returns null when objects is an empty array', () => {
    const message = { type: 'bundle', content: toBundle([]) };
    expect(buildSplitMessages(message)).toBeNull();
  });

  it('returns null when the bundle has no objects field at all', () => {
    const message = { type: 'bundle', content: Buffer.from(JSON.stringify({ id: 'bundle--test', type: 'bundle' }), 'utf-8').toString('base64') };
    expect(buildSplitMessages(message)).toBeNull();
  });

  it('returns null when objects is not an array (malformed payload)', () => {
    const message = { type: 'bundle', content: Buffer.from(JSON.stringify({ id: 'bundle--test', type: 'bundle', objects: 'not-an-array' }), 'utf-8').toString('base64') };
    expect(buildSplitMessages(message)).toBeNull();
  });

  it('throws a DatabaseError (not a raw crash) when content is missing entirely', () => {
    const message = { type: 'bundle' };
    expect(() => buildSplitMessages(message)).toThrow(/Invalid stix bundle content/);
  });

  it('throws a DatabaseError (not a raw crash) when content decodes to invalid JSON', () => {
    const message = { type: 'bundle', content: Buffer.from('not valid json{{{', 'utf-8').toString('base64') };
    expect(() => buildSplitMessages(message)).toThrow(/Invalid stix bundle content/);
  });

  it('treats no_split: false the same as no_split absent - still splits', () => {
    const objects = [{ id: 'malware--a', type: 'malware' }, { id: 'malware--b', type: 'malware' }];
    const message = { type: 'bundle', no_split: false, content: toBundle(objects) };
    const splitMessages = buildSplitMessages(message);
    expect(splitMessages).toHaveLength(2);
  });

  it('splits exactly at the boundary of 2 objects (smallest splittable size)', () => {
    const objects = [{ id: 'malware--a', type: 'malware' }, { id: 'malware--b', type: 'malware' }];
    const message = { type: 'bundle', content: toBundle(objects) };
    const splitMessages = buildSplitMessages(message);
    expect(splitMessages).toHaveLength(2);
  });

  it('dedupes objects sharing the same id, producing fewer split messages than raw array length', () => {
    // Two distinct array entries with the same id: pycti's raw_data is a dict keyed by id, so
    // the second entry silently overwrites/collapses into the first. The Node.js port must
    // preserve this exact dedup-by-id behavior rather than treating array length as authoritative.
    const objects = [
      { id: 'malware--dup', type: 'malware', name: 'First' },
      { id: 'malware--dup', type: 'malware', name: 'Second' },
      { id: 'malware--other', type: 'malware', name: 'Other' },
    ];
    const message = { type: 'bundle', content: toBundle(objects) };
    const splitMessages = buildSplitMessages(message);
    expect(splitMessages).toHaveLength(2);
  });

  it('throws when a multi-object bundle contains an object with no id (known pycti-parity limitation)', () => {
    // Unlike the single-object case (short-circuited before the splitter runs), a multi-object
    // bundle still reaches the dependency walk, which indexes objects by `id`. This matches
    // pycti's own behavior: raw_data[item["id"]] would raise KeyError on the exact same input.
    // Documented here as a known unsupported/malformed-bundle case, not a Node.js-specific bug.
    const objects = [
      { id: 'malware--a', type: 'malware' },
      { type: 'report', confidence: 100 }, // no id
    ];
    const message = { type: 'bundle', content: toBundle(objects) };
    expect(() => buildSplitMessages(message)).toThrow();
  });

  it('splits a larger bundle (20 objects) preserving every distinct id exactly once', () => {
    const objects = Array.from({ length: 20 }, (_, i) => ({ id: `malware--${i}`, type: 'malware', name: `Malware ${i}` }));
    const message = { type: 'bundle', content: toBundle(objects) };
    const splitMessages = buildSplitMessages(message);
    expect(splitMessages).toHaveLength(20);
    const ids = (splitMessages as { content: string }[]).map((msg) => decode(msg.content).objects[0].id);
    expect(new Set(ids)).toEqual(new Set(objects.map((o) => o.id)));
  });
});
