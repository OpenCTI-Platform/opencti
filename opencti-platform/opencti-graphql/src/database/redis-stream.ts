import { Cluster, Redis } from 'ioredis';
import * as R from 'ramda';
import { SEMATTRS_DB_NAME } from '@opentelemetry/semantic-conventions';
import conf, { logApp, REDIS_PREFIX } from '../config/conf';
import type { BaseEvent, DataEvent, SseEvent } from '../types/event';
import {
  ACTIVITY_STREAM_NAME,
  LIVE_STREAM_NAME,
  mapStreamToJS,
  NOTIFICATION_STREAM_NAME,
  processStreamResult,
  type RawStreamClient,
  type StreamOption,
  type StreamProcessor
} from './stream/stream-utils';
import { createRedisClient, getClientBase } from './redis';
import type { AuthContext, AuthUser } from '../types/user';
import { isEmptyField, wait, waitInSec } from './utils';
import { utcDate } from '../utils/format';
import { telemetry } from '../config/tracing';
import { UnsupportedError } from '../config/errors';

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

const rawPushToStream = async (context: AuthContext, user: AuthUser, eventMessage: string[]) => {
  const redisClient = getClientBase();
  const pushToStreamFn = async () => {
    if (streamTrimming) {
      await redisClient.call('XADD', REDIS_LIVE_STREAM_NAME, 'MAXLEN', '~', streamTrimming, '*', ...eventMessage);
    } else {
      await redisClient.call('XADD', REDIS_LIVE_STREAM_NAME, '*', ...eventMessage);
    }
  };
  await telemetry(context, user, 'INSERT STREAM', {
    [SEMATTRS_DB_NAME]: 'stream_engine',
  }, pushToStreamFn);
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
  opts: StreamOption = {}
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
        startEventId
      ) as any[];
      // Process the event results
      if (streamResult && streamResult.length > 0) {
        const [, results] = streamResult[0];
        const lastElementId = await processStreamResult(results, callback, opts.withInternal);
        startEventId = lastElementId || startEventId;
      } else {
        await processStreamResult([], callback, opts.withInternal);
      }
      await wait(opts.bufferTime ?? 50);
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
  opts: StreamOption = {},
) => {
  const { streamBatchSize = MAX_RANGE_MESSAGES, streamName = LIVE_STREAM_NAME, provider = 'fetchEventRange' } = opts;
  const redisStreamName = convertStreamName(streamName);
  let effectiveStartEventId = startEventId;
  const redisClient = await createRedisClient(provider, opts.autoReconnect); // Create client for this processing loop
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
      await processStreamResult(streamResult, callback, opts.withInternal); // process the stream events of the range
      if (lastStreamResultId) {
        effectiveStartEventId = lastStreamResultId;
      }
    } else {
      await processStreamResult([], callback, opts.withInternal);
    }
  } catch (err) {
    logApp.error('Redis stream consume fail', { cause: err });
    if (opts.autoReconnect) {
      await waitInSec(2);
    }
  } finally {
    redisClient.disconnect();
  }
  return { lastEventId: effectiveStartEventId };
};

// region opencti notification stream
const notificationTrimming = conf.get('redis:notification_trimming') || 50000;
const rawStoreNotificationEvent = async (event: string[]) => {
  await getClientBase().call('XADD', REDIS_NOTIFICATION_STREAM_NAME, 'MAXLEN', '~', notificationTrimming, '*', ...event);
};
const rawFetchRangeNotifications = async <T extends BaseEvent> (start: Date, end: Date): Promise<Array<T>> => {
  const streamResult = await getClientBase().call('XRANGE', REDIS_NOTIFICATION_STREAM_NAME, start.getTime(), end.getTime()) as any[];
  const streamElements: Array<SseEvent<T>> = streamResult.map((r) => mapStreamToJS(r));
  return streamElements.filter((s) => s.event === 'live').map((e) => e.data);
};
// endregion

// region opencti audit stream
const auditTrimming = conf.get('redis:activity_trimming') || 50000;
const rawStoreActivityEvent = async (event: string[]) => {
  await getClientBase().call('XADD', REDIS_ACTIVITY_STREAM_NAME, 'MAXLEN', '~', auditTrimming, '*', ...event);
};
// endregion

export const rawRedisStreamClient: RawStreamClient = {
  rawPushToStream,
  rawFetchStreamInfo,
  rawCreateStreamProcessor,
  rawFetchStreamEventsRangeFromEventId,
  rawStoreNotificationEvent,
  rawFetchRangeNotifications,
  rawStoreActivityEvent,
};
