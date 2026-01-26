import { Cluster, Redis } from 'ioredis';
import * as R from 'ramda';
import conf, { logApp, REDIS_PREFIX } from '../config/conf';
import type { ActivityStreamEvent, BaseEvent, DataEvent, SseEvent, StreamNotifEvent } from '../types/event';
import {
  ACTIVITY_STREAM_NAME,
  type FetchEventRangeOption,
  LIVE_STREAM_NAME,
  NOTIFICATION_STREAM_NAME,
  type RawStreamClient,
  type StreamProcessor,
  type StreamProcessorOption,
} from './stream/stream-utils';
import { createRedisClient, getClientBase, getClientXRANGE } from './redis';
import { isEmptyField, wait, waitInSec } from './utils';
import { utcDate } from '../utils/format';
import { UnsupportedError } from '../config/errors';
import { asyncMap } from '../utils/data-processing';

// region opencti data stream
const REDIS_LIVE_STREAM_NAME = `${REDIS_PREFIX}${LIVE_STREAM_NAME}`;
const REDIS_NOTIFICATION_STREAM_NAME = `${REDIS_PREFIX}${NOTIFICATION_STREAM_NAME}`;
const REDIS_ACTIVITY_STREAM_NAME = `${REDIS_PREFIX}${ACTIVITY_STREAM_NAME}`;
const streamTrimming = conf.get('redis:trimming') || 0;

const convertStreamName = (streamName = LIVE_STREAM_NAME) => {
  switch (streamName) {
    case ACTIVITY_STREAM_NAME:
      return REDIS_ACTIVITY_STREAM_NAME;
    case NOTIFICATION_STREAM_NAME:
      return REDIS_NOTIFICATION_STREAM_NAME;
    case LIVE_STREAM_NAME:
      return REDIS_LIVE_STREAM_NAME;
    default:
      throw UnsupportedError('Cannot recognize stream name', streamName);
  }
};

const mapJSToStream = (event: any) => {
  const cmdArgs: Array<string> = [];
  Object.keys(event).forEach((key) => {
    const value = event[key];
    if (value !== undefined) {
      cmdArgs.push(key);
      cmdArgs.push(JSON.stringify(value));
    }
  });
  return cmdArgs;
};
const mapStreamToJS = ([id, data]: any): SseEvent<any> => {
  const count = data.length / 2;
  const obj: any = {};
  for (let i = 0; i < count; i += 1) {
    obj[data[2 * i]] = JSON.parse(data[2 * i + 1]);
  }
  return { id, event: obj.type, data: obj };
};

const rawPushToStream = async <T extends BaseEvent> (event: T) => {
  const redisClient = getClientBase();
  const eventStreamData = mapJSToStream(event);
  if (streamTrimming) {
    await redisClient.call('XADD', REDIS_LIVE_STREAM_NAME, 'MAXLEN', '~', streamTrimming, '*', ...eventStreamData);
  } else {
    await redisClient.call('XADD', REDIS_LIVE_STREAM_NAME, '*', ...eventStreamData);
  }
};
const processStreamResult = async (results: Array<any>, callback: any, withInternal: boolean | undefined) => {
  const transform = (r: any) => mapStreamToJS(r);
  const filter = (s: any) => (withInternal ? true : (s.data.scope ?? 'external') === 'external');
  const events = await asyncMap(results, transform, filter);
  const lastEventId = events.length > 0 ? R.last(events)?.id : `${new Date().valueOf()}-0`;
  await callback(events, lastEventId);
  return lastEventId;
};
const rawFetchStreamInfo = async (streamName = LIVE_STREAM_NAME) => {
  const redisStreamName = convertStreamName(streamName);
  const res: any = await getClientBase().xinfo('STREAM', redisStreamName);
  const info: any = R.fromPairs(R.splitEvery(2, res) as any);
  const firstId = info['first-entry'][0];
  const firstEventDate = utcDate(parseInt(firstId.split('-')[0], 10)).toISOString();
  const lastId = info['last-entry'][0];
  const lastEventDate = utcDate(parseInt(lastId.split('-')[0], 10)).toISOString();
  return { lastEventId: lastId, firstEventId: firstId, firstEventDate, lastEventDate, streamSize: info.length };
};

const STREAM_BATCH_TIME = 5000;
const MAX_RANGE_MESSAGES = 100;

const rawCreateStreamProcessor = <T extends BaseEvent> (
  provider: string,
  callback: (events: Array<SseEvent<T>>, lastEventId: string) => Promise<void>,
  opts: StreamProcessorOption = {},
): StreamProcessor => {
  let client: Cluster | Redis;
  let startEventId: string;
  let processingLoopPromise: Promise<void>;
  let streamListening = true;
  const { streamName = LIVE_STREAM_NAME } = opts;
  const redisStreamName = convertStreamName(streamName);

  const processStep = async () => {
    // since previous call is async (and blocking) we should check if we are still running before processing the message
    if (!streamListening) {
      return false;
    }
    try {
      // Consume the data stream
      const streamResult = await client.call(
        'XREAD',
        'COUNT',
        MAX_RANGE_MESSAGES,
        'BLOCK',
        STREAM_BATCH_TIME,
        'STREAMS',
        redisStreamName,
        startEventId,
      ) as any[];
      // Process the event results
      if (streamResult && streamResult.length > 0) {
        const [, results] = streamResult[0];
        const lastElementId = await processStreamResult(results, callback, opts.withInternal);
        startEventId = lastElementId || startEventId;
      } else {
        await processStreamResult([], callback, opts.withInternal);
      }
      const bufferTime = opts.bufferTime ?? 50;
      if (bufferTime > 0) {
        await wait(bufferTime);
      }
    } catch (err) {
      logApp.error('Redis stream consume fail', { cause: err, provider });
      if (opts.autoReconnect) {
        await waitInSec(5);
      } else {
        return false;
      }
    }
    return streamListening;
  };
  const processingLoop = async () => {
    while (streamListening) {
      if (!(await processStep())) {
        streamListening = false;
        break;
      }
    }
  };
  return {
    info: async () => rawFetchStreamInfo(streamName),
    running: () => streamListening,
    start: async (start = 'live') => {
      if (streamListening) {
        let fromStart = start;
        if (isEmptyField(fromStart)) {
          fromStart = 'live';
        }
        startEventId = fromStart === 'live' ? '$' : fromStart;
        logApp.info('[STREAM] Starting stream processor', { provider, startEventId });
        processingLoopPromise = (async () => {
          client = await createRedisClient(provider, opts.autoReconnect); // Create client for this processing loop
          try {
            await processingLoop();
          } finally {
            logApp.info('[STREAM] Stream processor terminated, closing Redis client');
            client.disconnect();
          }
        })();
      }
    },
    shutdown: async () => {
      logApp.info('[STREAM] Shutdown stream processor', { provider });
      streamListening = false;
      if (processingLoopPromise) {
        await processingLoopPromise;
      }
      logApp.info('[STREAM] Stream processor current promise terminated');
    },
  };
};
// endregion

// region fetch stream event range
const rawFetchStreamEventsRangeFromEventId = async (
  startEventId: string,
  callback: (events: Array<SseEvent<DataEvent>>, lastEventId: string) => void,
  opts: FetchEventRangeOption = {},
) => {
  const { streamBatchSize = MAX_RANGE_MESSAGES, streamName = LIVE_STREAM_NAME, withInternal } = opts;
  const redisStreamName = convertStreamName(streamName);
  let effectiveStartEventId = startEventId;
  const redisClient = getClientXRANGE();
  try {
    // Consume streamBatchSize number of stream events from startEventId (excluded)
    const streamResult = await redisClient.call(
      'XRANGE',
      redisStreamName,
      `(${startEventId}`, // ( prefix to exclude startEventId
      '+',
      'COUNT',
      streamBatchSize,
    ) as any[];
    // Process the event results
    if (streamResult && streamResult.length > 0) {
      const lastStreamResultId = R.last(streamResult)[0]; // id of last event fetched (internal or external)
      await processStreamResult(streamResult, callback, withInternal); // process the stream events of the range
      if (lastStreamResultId) {
        effectiveStartEventId = lastStreamResultId;
      }
    } else {
      await processStreamResult([], callback, withInternal);
    }
  } catch (err) {
    logApp.error('Redis stream consume fail', { cause: err });
  }
  return { lastEventId: effectiveStartEventId };
};

// region opencti notification stream
const notificationTrimming = conf.get('redis:notification_trimming') || 50000;
const rawStoreNotificationEvent = async <T extends StreamNotifEvent> (event: T) => {
  const eventStreamData = mapJSToStream(event);
  await getClientBase().call('XADD', REDIS_NOTIFICATION_STREAM_NAME, 'MAXLEN', '~', notificationTrimming, '*', ...eventStreamData);
};
const rawFetchRangeNotifications = async <T extends StreamNotifEvent> (start: Date, end: Date): Promise<Array<T>> => {
  const streamResult = await getClientBase().call('XRANGE', REDIS_NOTIFICATION_STREAM_NAME, start.getTime(), end.getTime()) as any[];
  const streamElements: Array<SseEvent<T>> = streamResult.map((r) => mapStreamToJS(r));
  return streamElements.filter((s) => s.event === 'live').map((e) => e.data);
};
// endregion

// region opencti audit stream
const auditTrimming = conf.get('redis:activity_trimming') || 50000;
const rawStoreActivityEvent = async (event: ActivityStreamEvent) => {
  const eventStreamData = mapJSToStream(event);
  await getClientBase().call('XADD', REDIS_ACTIVITY_STREAM_NAME, 'MAXLEN', '~', auditTrimming, '*', ...eventStreamData);
};
// endregion

export const rawRedisStreamClient: RawStreamClient = {
  initializeStreams: async () => {},
  rawPushToStream,
  rawFetchStreamInfo,
  rawCreateStreamProcessor,
  rawFetchStreamEventsRangeFromEventId,
  rawStoreNotificationEvent,
  rawFetchRangeNotifications,
  rawStoreActivityEvent,
};
