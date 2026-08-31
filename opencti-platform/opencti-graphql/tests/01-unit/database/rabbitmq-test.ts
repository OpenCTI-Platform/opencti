import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mockHttpClient = {
  get: vi.fn(),
  delete: vi.fn(),
};

vi.mock('../../../src/utils/http-client', () => ({
  getHttpClient: vi.fn(() => mockHttpClient),
}));

// Fake confirm channel: publish() immediately acks via the confirm callback, so
// pushBundleToWorker's real send() resolves synchronously without a broker.
const mockChannelPublish = vi.fn((_exchange, _routingKey, _content, _options, callback) => {
  callback(null);
  return true;
});
const mockChannel = {
  on: vi.fn(),
  publish: mockChannelPublish,
};
const mockConnection = {
  on: vi.fn(),
  close: vi.fn(),
  createConfirmChannel: vi.fn((cb) => cb(null, mockChannel)),
};
vi.mock('amqplib/callback_api', () => ({
  default: {
    connect: vi.fn((_uri, _options, callback) => callback(null, mockConnection)),
    credentials: { plain: vi.fn() },
  },
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

import { updateExpectationsNumber } from '../../../src/domain/work';
import { buildSplitMessages, getConnectorQueueSize, metrics, pushBundleToWorker } from '../../../src/database/rabbitmq';

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

  it('returns the original message unsplit, with a null expectations count, for non-bundle messages', () => {
    const message = { type: 'event', content: 'irrelevant' };
    expect(buildSplitMessages(message)).toEqual({ messages: [message], expectations: null });
  });

  it('returns the original message unsplit for messages explicitly marked no_split', () => {
    const message = {
      type: 'bundle',
      no_split: true,
      content: toBundle([{ id: 'malware--a', type: 'malware' }, { id: 'malware--b', type: 'malware' }]),
    };
    const result = buildSplitMessages(message);
    expect(result.messages).toEqual([message]);
    expect(result.expectations).toBe(2);
  });

  it('returns the original message unsplit for single-object bundles', () => {
    const message = { type: 'bundle', content: toBundle([{ id: 'malware--only', type: 'malware', name: 'Only' }]) };
    const result = buildSplitMessages(message);
    expect(result.messages).toEqual([message]);
    expect(result.expectations).toBe(1);
  });

  it('returns the original message unsplit for a single-object bundle even when the object has no id (malformed/partial STIX)', () => {
    // Regression test: a real TAXII response can contain an object with no `id` field.
    // The splitter's dependency walk cannot safely handle that, so single-object bundles
    // must be short-circuited before ever invoking it - mirroring the worker's own
    // `len(content['objects']) == 1` pre-check in push_handler.py.
    const message = { type: 'bundle', content: toBundle([{ type: 'report', confidence: 100 }]) };
    const result = buildSplitMessages(message);
    expect(result.messages).toEqual([message]);
    expect(result.expectations).toBe(1);
  });

  it('splits a multi-object bundle into one message per object, preserving other fields', () => {
    const objects = [
      { id: 'marking-definition--m1', type: 'marking-definition', definition_type: 'tlp', name: 'TLP:RED' },
      { id: 'malware--m', type: 'malware', name: 'Mal', object_marking_refs: ['marking-definition--m1'] },
      { id: 'indicator--i', type: 'indicator', name: 'Ind', pattern: "[file:hashes.MD5 = 'x']", object_marking_refs: ['marking-definition--m1'] },
      { id: 'relationship--r', type: 'relationship', relationship_type: 'based-on', source_ref: 'indicator--i', target_ref: 'malware--m' },
    ];
    const message = { type: 'bundle', content: toBundle(objects), work_id: 'work-1', applicant_id: 'user-1', update: true };

    const { messages: splitMessages, expectations } = buildSplitMessages(message);

    expect(splitMessages).toHaveLength(objects.length);
    expect(expectations).toBe(objects.length);
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

  it('returns expectations 0 and the original message unsplit when objects is an empty array', () => {
    const message = { type: 'bundle', content: toBundle([]) };
    const result = buildSplitMessages(message);
    expect(result.messages).toEqual([message]);
    expect(result.expectations).toBe(0);
  });

  it('returns expectations 0 and the original message unsplit when the bundle has no objects field at all', () => {
    const message = { type: 'bundle', content: Buffer.from(JSON.stringify({ id: 'bundle--test', type: 'bundle' }), 'utf-8').toString('base64') };
    const result = buildSplitMessages(message);
    expect(result.messages).toEqual([message]);
    expect(result.expectations).toBe(0);
  });

  it('returns expectations 0 and the original message unsplit when objects is not an array (malformed payload)', () => {
    const message = { type: 'bundle', content: Buffer.from(JSON.stringify({ id: 'bundle--test', type: 'bundle', objects: 'not-an-array' }), 'utf-8').toString('base64') };
    const result = buildSplitMessages(message);
    expect(result.messages).toEqual([message]);
    expect(result.expectations).toBe(0);
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
    const { messages: splitMessages, expectations } = buildSplitMessages(message);
    expect(splitMessages).toHaveLength(2);
    expect(expectations).toBe(2);
  });

  it('splits exactly at the boundary of 2 objects (smallest splittable size)', () => {
    const objects = [{ id: 'malware--a', type: 'malware' }, { id: 'malware--b', type: 'malware' }];
    const message = { type: 'bundle', content: toBundle(objects) };
    const { messages: splitMessages } = buildSplitMessages(message);
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
    const { messages: splitMessages, expectations } = buildSplitMessages(message);
    expect(splitMessages).toHaveLength(2);
    expect(expectations).toBe(2);
  });

  it('reports the deduped expectations count (not the raw object count) when dedup collapses a multi-object bundle down to a single message', () => {
    // Regression test: two array entries sharing the same id collapse to a single bundle after
    // dedup. The raw objectCount (2) must never leak into expectations/messages here - doing so
    // previously caused the worker to see a non-no_split message and re-split/re-count on top.
    const objects = [
      { id: 'malware--dup', type: 'malware', name: 'First' },
      { id: 'malware--dup', type: 'malware', name: 'Second' },
    ];
    const message = { type: 'bundle', work_id: 'work-1', content: toBundle(objects) };
    const { messages: splitMessages, expectations } = buildSplitMessages(message);
    expect(splitMessages).toHaveLength(1);
    expect(expectations).toBe(1);
    expect((splitMessages[0] as { no_split: boolean }).no_split).toBe(true);
    expect(decode((splitMessages[0] as { content: string }).content).objects).toHaveLength(1);
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
    const { messages: splitMessages, expectations } = buildSplitMessages(message);
    expect(splitMessages).toHaveLength(20);
    expect(expectations).toBe(20);
    const ids = (splitMessages as { content: string }[]).map((msg) => decode(msg.content).objects[0].id);
    expect(new Set(ids)).toEqual(new Set(objects.map((o) => o.id)));
  });
});

describe('rabbitmq: pushBundleToWorker (centralized expectations tracking)', () => {
  const toBundle = (objects: unknown[]) => Buffer.from(JSON.stringify({ id: 'bundle--test', type: 'bundle', objects }), 'utf-8').toString('base64');
  const decode = (base64Content: string) => JSON.parse(Buffer.from(base64Content, 'base64').toString('utf-8'));
  const context = {};
  const user = {};

  beforeEach(() => {
    vi.clearAllMocks();
    mockChannelPublish.mockImplementation((_exchange, _routingKey, _content, _options, callback) => {
      callback(null);
      return true;
    });
    mockConnection.createConfirmChannel.mockImplementation((cb: (err: unknown, channel: unknown) => void) => cb(null, mockChannel));
  });

  it('tracks expectations for a single-object bundle whenever a work_id is present', async () => {
    const objects = [{ id: 'malware--a', type: 'malware' }];
    const message = { type: 'bundle', content: toBundle(objects), work_id: 'work-1' };

    await pushBundleToWorker(context, user, 'connector-1', message);

    expect(updateExpectationsNumber).toHaveBeenCalledTimes(1);
    expect(updateExpectationsNumber).toHaveBeenCalledWith(context, user, 'work-1', 1);
    expect(mockChannelPublish).toHaveBeenCalledTimes(1);
  });

  it('does NOT track expectations when work_id is missing', async () => {
    const objects = [{ id: 'malware--a', type: 'malware' }];
    const message = { type: 'bundle', content: toBundle(objects) };

    await pushBundleToWorker(context, user, 'connector-1', message);

    expect(updateExpectationsNumber).not.toHaveBeenCalled();
    expect(mockChannelPublish).toHaveBeenCalledTimes(1);
  });

  it('does NOT track expectations for non-bundle messages (e.g. sync "event" type), even with a work_id present', async () => {
    // buildSplitMessages returns expectations: null for non-bundle messages, so `expectations > 0` is false.
    const message = { type: 'event', event_id: 'evt-1', work_id: 'work-1' };

    await pushBundleToWorker(context, user, 'connector-1', message);

    expect(updateExpectationsNumber).not.toHaveBeenCalled();
    expect(mockChannelPublish).toHaveBeenCalledTimes(1);
  });

  it('tracks the true post-split expectation count (not raw message count) for a multi-object bundle', async () => {
    const objects = [
      { id: 'malware--a', type: 'malware' },
      { id: 'malware--b', type: 'malware' },
      { id: 'malware--c', type: 'malware' },
    ];
    const message = { type: 'bundle', content: toBundle(objects), work_id: 'work-1' };

    await pushBundleToWorker(context, user, 'connector-1', message);

    expect(updateExpectationsNumber).toHaveBeenCalledTimes(1);
    expect(updateExpectationsNumber).toHaveBeenCalledWith(context, user, 'work-1', 3);
    // One publish per split object, since the bundle was split into 3 single-object messages.
    expect(mockChannelPublish).toHaveBeenCalledTimes(3);
  });

  it('tracks the deduplicated expectation count, not the raw pre-dedup object count, for a bundle with duplicate ids', async () => {
    const objects = [
      { id: 'malware--dup', type: 'malware', name: 'First' },
      { id: 'malware--dup', type: 'malware', name: 'Second' },
      { id: 'malware--other', type: 'malware' },
    ];
    const message = { type: 'bundle', content: toBundle(objects), work_id: 'work-1' };

    await pushBundleToWorker(context, user, 'connector-1', message);

    expect(updateExpectationsNumber).toHaveBeenCalledWith(context, user, 'work-1', 2);
    expect(mockChannelPublish).toHaveBeenCalledTimes(2);
  });

  it('calls updateExpectationsNumber before publishing any split message (expectations must be visible before completion signals can arrive)', async () => {
    const callOrder: string[] = [];
    vi.mocked(updateExpectationsNumber).mockImplementation(async () => {
      callOrder.push('updateExpectationsNumber');
      return 'work-1';
    });
    mockChannelPublish.mockImplementation((_exchange, _routingKey, _content, _options, callback) => {
      callOrder.push('publish');
      callback(null);
      return true;
    });
    const objects = [{ id: 'malware--a', type: 'malware' }, { id: 'malware--b', type: 'malware' }];
    const message = { type: 'bundle', content: toBundle(objects), work_id: 'work-1' };

    await pushBundleToWorker(context, user, 'connector-1', message);

    expect(callOrder).toEqual(['updateExpectationsNumber', 'publish', 'publish']);
  });

  it('publishes split messages in the splitter dependency-sorted order, preserving FIFO publish order', async () => {
    const publishedIds: string[] = [];
    mockChannelPublish.mockImplementation((_exchange, _routingKey, content: Buffer, _options, callback) => {
      const published = JSON.parse(content.toString());
      publishedIds.push(decode(published.content).objects[0].id);
      callback(null);
      return true;
    });
    // A relationship depends on both endpoints, so it must sort (and publish) after them.
    const objects = [
      { id: 'relationship--rel', type: 'relationship', source_ref: 'malware--a', target_ref: 'malware--b' },
      { id: 'malware--a', type: 'malware' },
      { id: 'malware--b', type: 'malware' },
    ];
    const message = { type: 'bundle', content: toBundle(objects), work_id: 'work-1' };

    await pushBundleToWorker(context, user, 'connector-1', message);

    expect(publishedIds.indexOf('relationship--rel')).toBeGreaterThan(publishedIds.indexOf('malware--a'));
    expect(publishedIds.indexOf('relationship--rel')).toBeGreaterThan(publishedIds.indexOf('malware--b'));
  });

  it('publishes the single unsplit message unchanged when no split occurs, without invoking the splitter logic on it', async () => {
    const objects = [{ id: 'malware--a', type: 'malware' }];
    const message = { type: 'bundle', content: toBundle(objects), work_id: 'work-1', applicant_id: 'user-1' };

    await pushBundleToWorker(context, user, 'connector-1', message);

    const [, , publishedBuffer] = mockChannelPublish.mock.calls[0];
    const publishedMessage = JSON.parse(publishedBuffer.toString());
    expect(publishedMessage.content).toBe(message.content);
    expect(publishedMessage.applicant_id).toBe('user-1');
  });

  it('publishes a valid multi-object bundle split into one message per distinct object (happy path baseline)', async () => {
    const objects = [
      { id: 'malware--a', type: 'malware' },
      { id: 'malware--b', type: 'malware' },
    ];
    const message = { type: 'bundle', content: toBundle(objects), work_id: 'work-1' };

    await pushBundleToWorker(context, user, 'connector-1', message);

    expect(mockChannelPublish).toHaveBeenCalledTimes(2);
    expect(updateExpectationsNumber).toHaveBeenCalledWith(context, user, 'work-1', 2);
    const publishedIds = mockChannelPublish.mock.calls.map(([, , content]) => decode(JSON.parse(content.toString()).content).objects[0].id);
    expect(publishedIds).toEqual(['malware--a', 'malware--b']);
  });

  it('still publishes an unparseable bundle unsplit and untouched, without tracking expectations, instead of blocking (invalid input parity with pre-split behavior)', async () => {
    const message = {
      type: 'bundle',
      content: Buffer.from('not valid json{{{', 'utf-8').toString('base64'),
      work_id: 'work-1',
    };

    await expect(pushBundleToWorker(context, user, 'connector-1', message)).rejects.toThrow(/Invalid stix bundle content/);

    expect(updateExpectationsNumber).not.toHaveBeenCalled();
    expect(mockChannelPublish).not.toHaveBeenCalled();
  });

  it('rejects a bundle with missing content instead of publishing it', async () => {
    const message = { type: 'bundle', work_id: 'work-1' };

    await expect(pushBundleToWorker(context, user, 'connector-1', message)).rejects.toThrow(/Invalid stix bundle content/);

    expect(updateExpectationsNumber).not.toHaveBeenCalled();
    expect(mockChannelPublish).not.toHaveBeenCalled();
  });
});
