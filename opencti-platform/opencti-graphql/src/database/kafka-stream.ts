import { type Admin, type Consumer, Kafka, type KafkaMessage, type ITopicConfig, type Producer, logLevel, type SASLOptions } from 'kafkajs';
import { v4 as uuidv4 } from 'uuid';
import * as R from 'ramda';
import conf, { booleanConf, logApp } from '../config/conf';
import type { BaseEvent, SseEvent, StreamNotifEvent, ActivityStreamEvent } from '../types/event';
import {
  ACTIVITY_STREAM_NAME,
  type FetchEventRangeOption,
  LIVE_STREAM_NAME,
  NOTIFICATION_STREAM_NAME,
  type RawStreamClient,
  type SizedNotifEvent,
  type StreamInfo,
  type StreamProcessor,
  type StreamProcessorOption,
} from './stream/stream-utils';
import { isEmptyField, wait, waitInSec } from './utils';
import { utcDate } from '../utils/format';
import { UnsupportedError } from '../config/errors';

// region configuration
// Streams are stored as Kafka topics. To keep the same behavior as the Redis stream implementation
// (a single, globally ordered stream where each event gets a monotonic id and a server side timestamp),
// each stream is backed by a single-partition topic and every message is stamped by the broker
// (message.timestamp.type = LogAppendTime). The event id has the exact same shape as the Redis one:
//   `<serverTimestampMs>-<partitionOffset>`
// so downstream code parsing `id.split('-')[0]` as a timestamp keeps working, and the offset part is
// used as the resumable cursor.
const KAFKA_PREFIX = conf.get('kafka:namespace') ? `${conf.get('kafka:namespace')}.` : '';
const KAFKA_NUM_PARTITIONS = conf.get('kafka:num_partitions') ?? 1;
const KAFKA_REPLICATION_FACTOR = conf.get('kafka:replication_factor') ?? 1;
const KAFKA_RETENTION_MS = conf.get('kafka:retention_ms') ?? 604800000; // 7 days by default
const KAFKA_USE_SSL = booleanConf('kafka:use_ssl', false);
const KAFKA_SASL_ENABLED = booleanConf('kafka:sasl_enabled', false);
const STREAM_PARTITION = 0;
const STREAM_BATCH_TIME = 5000;
const MAX_RANGE_MESSAGES = 100;
// Number of notification stream entries fetched per range batch when computing digests (see redis-stream for rationale).
const notificationRangeBatchSize = conf.get('redis:notification_range_batch_size') || 1000;

const KAFKA_LIVE_STREAM_NAME = `${KAFKA_PREFIX}${LIVE_STREAM_NAME}`;
const KAFKA_NOTIFICATION_STREAM_NAME = `${KAFKA_PREFIX}${NOTIFICATION_STREAM_NAME}`;
const KAFKA_ACTIVITY_STREAM_NAME = `${KAFKA_PREFIX}${ACTIVITY_STREAM_NAME}`;

const convertStreamName = (streamName = LIVE_STREAM_NAME): string => {
  switch (streamName) {
    case ACTIVITY_STREAM_NAME:
      return KAFKA_ACTIVITY_STREAM_NAME;
    case NOTIFICATION_STREAM_NAME:
      return KAFKA_NOTIFICATION_STREAM_NAME;
    case LIVE_STREAM_NAME:
      return KAFKA_LIVE_STREAM_NAME;
    default:
      throw UnsupportedError('Cannot recognize stream name', { streamName });
  }
};
// endregion

// region kafka clients (lazy singletons)
let kafkaInstance: Kafka | undefined;
const getKafka = (): Kafka => {
  if (!kafkaInstance) {
    const sasl: SASLOptions | undefined = KAFKA_SASL_ENABLED ? {
      mechanism: conf.get('kafka:sasl_mechanism') ?? 'plain',
      username: conf.get('kafka:sasl_username'),
      password: conf.get('kafka:sasl_password'),
    } as SASLOptions : undefined;
    kafkaInstance = new Kafka({
      clientId: conf.get('kafka:client_id') ?? 'opencti',
      brokers: conf.get('kafka:brokers') ?? ['localhost:9092'],
      ssl: KAFKA_USE_SSL,
      sasl,
      connectionTimeout: conf.get('kafka:connection_timeout') ?? 10000,
      requestTimeout: conf.get('kafka:request_timeout') ?? 30000,
      logLevel: logLevel.NOTHING,
    });
  }
  return kafkaInstance;
};

// A single shared producer is enough for all writes (it is thread safe and multiplexed).
const getProducer = (() => {
  let connected: Promise<Producer> | undefined;
  return (): Promise<Producer> => {
    if (!connected) {
      const producer = getKafka().producer({ allowAutoTopicCreation: false, idempotent: false });
      connected = producer.connect().then(() => producer);
    }
    return connected;
  };
})();

const withAdmin = async <T> (fn: (admin: Admin) => Promise<T>): Promise<T> => {
  const admin = getKafka().admin();
  await admin.connect();
  try {
    return await fn(admin);
  } finally {
    await admin.disconnect();
  }
};
// endregion

// region serialization helpers
const buildEventId = (timestampMs: string | number, offset: string | number): string => {
  return `${timestampMs}-${offset}`;
};

// The offset part of the event id is the resumable cursor within the partition.
const parseOffsetFromEventId = (eventId: string): bigint => {
  const parts = eventId.split('-');
  // id shape is `<timestamp>-<offset>`
  const rawOffset = parts.length > 1 ? parts[parts.length - 1] : parts[0];
  try {
    return BigInt(rawOffset);
  } catch {
    return 0n;
  }
};

const mapMessageToJS = (message: KafkaMessage): SseEvent<any> => {
  const value = message.value ? message.value.toString('utf-8') : '{}';
  const data = JSON.parse(value);
  const id = buildEventId(message.timestamp, message.offset);
  return { id, event: data.type, data };
};

const rawMessageByteSize = (message: KafkaMessage): number => {
  return message.value ? message.value.length : 0;
};
// endregion

// region processing helpers
const processStreamResult = async (
  events: Array<SseEvent<any>>,
  callback: (events: Array<SseEvent<any>>, lastEventId: string) => Promise<void> | void,
  withInternal: boolean | undefined,
  currentLastEventId: string,
) => {
  const filtered = withInternal ? events : events.filter((s) => (s.data.scope ?? 'external') === 'external');
  const lastEventId = events.length > 0 ? (R.last(events)?.id ?? currentLastEventId) : currentLastEventId;
  await callback(filtered, lastEventId);
  return lastEventId;
};

// Fetch the earliest (low) and next-to-be-written (high) offsets for the stream partition.
const fetchPartitionBounds = async (topic: string): Promise<{ low: bigint; high: bigint }> => {
  return withAdmin(async (admin) => {
    const offsets = await admin.fetchTopicOffsets(topic);
    const partitionOffsets = offsets.find((o) => o.partition === STREAM_PARTITION) ?? offsets[0];
    return { low: BigInt(partitionOffsets.low), high: BigInt(partitionOffsets.high) };
  });
};

// Read a bounded range of raw Kafka messages [startOffset, endOffsetExclusive) up to maxCount messages.
// A dedicated ephemeral consumer is used (no consumer group load balancing) so each read sees the whole stream.
const consumeRawRange = async (
  topic: string,
  startOffset: bigint,
  maxCount: number,
  endOffsetExclusive: bigint,
): Promise<KafkaMessage[]> => {
  if (startOffset >= endOffsetExclusive || maxCount <= 0) {
    return [];
  }
  const consumer = getKafka().consumer({ groupId: `opencti-range-${uuidv4()}`, allowAutoTopicCreation: false });
  const collected: KafkaMessage[] = [];
  await consumer.connect();
  try {
    await consumer.subscribe({ topic, fromBeginning: true });
    await new Promise<void>((resolve) => {
      let settled = false;
      const finish = () => {
        if (!settled) {
          settled = true;
          resolve();
        }
      };
      // Safety timeout so the read resolves even if there are fewer messages than expected.
      const timer = setTimeout(finish, STREAM_BATCH_TIME);
      consumer.run({
        autoCommit: false,
        eachBatchAutoResolve: false,
        eachBatch: async ({ batch, resolveOffset, heartbeat, isRunning, isStale }) => {
          for (const message of batch.messages) {
            if (!isRunning() || isStale() || settled) break;
            const offset = BigInt(message.offset);
            if (offset < startOffset) {
              // Message before the requested start (can happen on batch boundaries) => just acknowledge it.
              resolveOffset(message.offset);
            } else if (offset >= endOffsetExclusive || collected.length >= maxCount) {
              clearTimeout(timer);
              finish();
              return;
            } else {
              collected.push(message);
              resolveOffset(message.offset);
              if (collected.length >= maxCount || offset + 1n >= endOffsetExclusive) {
                clearTimeout(timer);
                finish();
                return;
              }
            }
          }
          await heartbeat();
        },
      }).catch(() => finish());
      // Seek is buffered by kafkajs until the partition is assigned.
      consumer.seek({ topic, partition: STREAM_PARTITION, offset: startOffset.toString() });
    });
  } finally {
    await consumer.disconnect();
  }
  return collected;
};

const readMessageAtOffset = async (topic: string, offset: bigint): Promise<KafkaMessage | undefined> => {
  const messages = await consumeRawRange(topic, offset, 1, offset + 1n);
  return messages[0];
};
// endregion

// region RawStreamClient implementation
const initializeStreams = async (): Promise<void> => {
  if (!booleanConf('kafka:enabled', false)) {
    return;
  }
  const topicConfig: ITopicConfig[] = [
    KAFKA_LIVE_STREAM_NAME,
    KAFKA_NOTIFICATION_STREAM_NAME,
    KAFKA_ACTIVITY_STREAM_NAME,
  ].map((topic) => ({
    topic,
    numPartitions: KAFKA_NUM_PARTITIONS,
    replicationFactor: KAFKA_REPLICATION_FACTOR,
    configEntries: [
      // Broker assigns the timestamp => server side timestamp, like Redis XADD id.
      { name: 'message.timestamp.type', value: 'LogAppendTime' },
      // Retention replaces the Redis stream trimming (MAXLEN).
      { name: 'retention.ms', value: `${KAFKA_RETENTION_MS}` },
    ],
  }));
  await withAdmin(async (admin) => {
    await admin.createTopics({ topics: topicConfig, waitForLeaders: true });
  });
  logApp.info('[STREAM] Kafka streams initialized', { topics: topicConfig.map((t) => t.topic) });
};

const pushToTopic = async (topic: string, event: BaseEvent): Promise<void> => {
  const producer = await getProducer();
  await producer.send({
    topic,
    messages: [{ value: JSON.stringify(event) }],
  });
};

const rawPushToStream = async <T extends BaseEvent> (event: T): Promise<void> => {
  await pushToTopic(KAFKA_LIVE_STREAM_NAME, event);
};

const rawStoreNotificationEvent = async <T extends StreamNotifEvent> (event: T): Promise<void> => {
  await pushToTopic(KAFKA_NOTIFICATION_STREAM_NAME, event);
};

const rawStoreActivityEvent = async (event: ActivityStreamEvent): Promise<void> => {
  await pushToTopic(KAFKA_ACTIVITY_STREAM_NAME, event as unknown as BaseEvent);
};

const rawFetchStreamInfo = async (streamName = LIVE_STREAM_NAME): Promise<StreamInfo> => {
  const topic = convertStreamName(streamName);
  const { low, high } = await fetchPartitionBounds(topic);
  const streamSize = Number(high - low);
  // Empty stream: mirror an "empty" info with current date bounds.
  if (high <= low) {
    const nowId = `${new Date().valueOf()}-0`;
    const nowDate = utcDate().toISOString();
    return { lastEventId: nowId, firstEventId: nowId, firstEventDate: nowDate, lastEventDate: nowDate, streamSize: 0 };
  }
  const firstMessage = await readMessageAtOffset(topic, low);
  const lastMessage = await readMessageAtOffset(topic, high - 1n);
  const firstId = firstMessage ? buildEventId(firstMessage.timestamp, firstMessage.offset) : `${low}`;
  const lastId = lastMessage ? buildEventId(lastMessage.timestamp, lastMessage.offset) : `${high - 1n}`;
  const firstEventDate = utcDate(firstMessage ? parseInt(firstMessage.timestamp, 10) : Date.now()).toISOString();
  const lastEventDate = utcDate(lastMessage ? parseInt(lastMessage.timestamp, 10) : Date.now()).toISOString();
  return { lastEventId: lastId, firstEventId: firstId, firstEventDate, lastEventDate, streamSize };
};

const rawFetchStreamEventsRangeFromEventId = async <T extends BaseEvent> (
  startEventId: string,
  callback: (events: Array<SseEvent<T>>, lastEventId: string) => void,
  opts: FetchEventRangeOption = {},
): Promise<{ lastEventId: string }> => {
  const { streamBatchSize = MAX_RANGE_MESSAGES, streamName = LIVE_STREAM_NAME, withInternal } = opts;
  const topic = convertStreamName(streamName);
  let effectiveStartEventId = startEventId;
  try {
    const { high } = await fetchPartitionBounds(topic);
    // The event id offset is excluded (we resume strictly after it), like the Redis `(id` XRANGE prefix.
    const fromOffset = parseOffsetFromEventId(startEventId) + 1n;
    const messages = await consumeRawRange(topic, fromOffset, streamBatchSize, high);
    if (messages.length > 0) {
      const events = messages.map((m) => mapMessageToJS(m) as SseEvent<T>);
      const lastEventId = R.last(events)?.id ?? startEventId;
      await processStreamResult(events, callback as any, withInternal, startEventId);
      effectiveStartEventId = lastEventId;
    } else {
      await processStreamResult([], callback as any, withInternal, startEventId);
    }
  } catch (err) {
    logApp.error('Kafka stream consume fail', { cause: err });
  }
  return { lastEventId: effectiveStartEventId };
};

const rawFetchRangeNotifications = async <T extends StreamNotifEvent> (
  start: Date,
  end: Date,
  callback: (events: Array<SizedNotifEvent<T>>) => Promise<boolean | void> | boolean | void,
): Promise<void> => {
  const topic = KAFKA_NOTIFICATION_STREAM_NAME;
  const bounds = await fetchPartitionBounds(topic);
  // Resolve the offset boundaries from the timestamps (broker side).
  const startOffset = await withAdmin(async (admin) => {
    const res = await admin.fetchTopicOffsetsByTimestamp(topic, start.getTime());
    const partitionOffset = res.find((o) => o.partition === STREAM_PARTITION) ?? res[0];
    return partitionOffset ? BigInt(partitionOffset.offset) : bounds.low;
  });
  const endOffset = await withAdmin(async (admin) => {
    const res = await admin.fetchTopicOffsetsByTimestamp(topic, end.getTime());
    const partitionOffset = res.find((o) => o.partition === STREAM_PARTITION) ?? res[0];
    // fetchTopicOffsetsByTimestamp returns -1 when the timestamp is beyond the last message.
    const value = partitionOffset ? BigInt(partitionOffset.offset) : bounds.high;
    return value < 0n ? bounds.high : value;
  });
  let cursor = startOffset;
  for (;;) {
    if (cursor >= endOffset) {
      break;
    }
    const messages = await consumeRawRange(topic, cursor, notificationRangeBatchSize, endOffset);
    if (messages.length === 0) {
      break;
    }
    const events: Array<SizedNotifEvent<T>> = [];
    for (let i = 0; i < messages.length; i += 1) {
      const parsed = mapMessageToJS(messages[i]);
      if (parsed.event === 'live') {
        events.push({ event: parsed.data as T, byteSize: rawMessageByteSize(messages[i]) });
      }
    }
    if (events.length > 0) {
      const shouldContinue = await callback(events);
      if (shouldContinue === false) {
        break;
      }
    }
    // Advance the cursor after the last consumed offset.
    cursor = BigInt(R.last(messages)!.offset) + 1n;
    if (messages.length < notificationRangeBatchSize) {
      break;
    }
  }
};

const rawCreateStreamProcessor = <T extends BaseEvent> (
  provider: string,
  callback: (events: Array<SseEvent<T>>, lastEventId: string) => Promise<void>,
  opts: StreamProcessorOption = {},
): StreamProcessor => {
  let consumer: Consumer | undefined;
  let processingLoopPromise: Promise<void> | undefined;
  let streamListening = true;
  let currentLastEventId = '0-0';
  const { streamName = LIVE_STREAM_NAME } = opts;
  const topic = convertStreamName(streamName);

  const runConsumer = async (fromOffset: bigint) => {
    consumer = getKafka().consumer({
      groupId: `opencti-processor-${provider.replaceAll(' ', '_')}-${uuidv4()}`,
      allowAutoTopicCreation: false,
    });
    await consumer.connect();
    await consumer.subscribe({ topic, fromBeginning: true });
    await consumer.run({
      autoCommit: false,
      eachBatchAutoResolve: false,
      eachBatch: async ({ batch, resolveOffset, heartbeat, isRunning, isStale }) => {
        if (!streamListening || !isRunning() || isStale()) {
          return;
        }
        const events = batch.messages.map((m) => mapMessageToJS(m) as SseEvent<T>);
        if (events.length > 0) {
          currentLastEventId = await processStreamResult(events, callback, opts.withInternal, currentLastEventId);
          for (let i = 0; i < batch.messages.length; i += 1) {
            resolveOffset(batch.messages[i].offset);
          }
        }
        await heartbeat();
        const bufferTime = opts.bufferTime ?? 50;
        if (bufferTime > 0 && streamListening) {
          await wait(bufferTime);
        }
      },
    });
    // Seek is buffered by kafkajs until the partition is assigned.
    consumer.seek({ topic, partition: STREAM_PARTITION, offset: fromOffset.toString() });
  };

  return {
    info: async () => rawFetchStreamInfo(streamName),
    running: () => streamListening,
    start: async (start = 'live') => {
      if (!streamListening) {
        return;
      }
      let fromStart = start;
      if (isEmptyField(fromStart)) {
        fromStart = 'live';
      }
      const { high } = await fetchPartitionBounds(topic);
      // 'live' => only new events (start at the end of the stream), otherwise resume strictly after the given id.
      const fromOffset = fromStart === 'live' ? high : parseOffsetFromEventId(fromStart as string) + 1n;
      logApp.info('[STREAM] Starting Kafka stream processor', { provider, fromOffset: fromOffset.toString() });
      processingLoopPromise = (async () => {
        try {
          await runConsumer(fromOffset);
        } catch (err) {
          if (streamListening) {
            logApp.error('Kafka stream processor fail', { cause: err, provider });
            if (opts.autoReconnect) {
              await waitInSec(5);
            }
          }
        }
      })();
    },
    shutdown: async () => {
      logApp.info('[STREAM] Shutdown Kafka stream processor', { provider });
      streamListening = false;
      if (consumer) {
        await consumer.disconnect().catch(() => {});
      }
      if (processingLoopPromise) {
        await processingLoopPromise;
      }
      logApp.info('[STREAM] Kafka stream processor current promise terminated', { provider });
    },
  };
};
// endregion

export const rawKafkaStreamClient: RawStreamClient = {
  initializeStreams,
  rawPushToStream,
  rawFetchStreamInfo,
  rawCreateStreamProcessor,
  rawFetchStreamEventsRangeFromEventId,
  rawStoreNotificationEvent,
  rawFetchRangeNotifications,
  rawStoreActivityEvent,
};
