import type { ActivityStreamEvent, BaseEvent, DataEvent, SseEvent, StreamNotifEvent } from '../../types/event';
import {
  type FetchEventRangeOption,
  LIVE_STREAM_NAME,
  NOTIFICATION_STREAM_NAME,
  type RawStreamClient,
  type StreamInfo,
  type StreamProcessor,
  type StreamProcessorOption,
} from './stream-utils';
import { rawRedisStreamClient } from '../redis-stream';
import { rawRabbitMQStreamClient } from '../rabbitmq-stream';
import { utcDate } from '../../utils/format';
import { logApp } from '../../config/conf';

const redisStreamClient: RawStreamClient = rawRedisStreamClient;
const rabbitStreamClient: RawStreamClient = rawRabbitMQStreamClient;

// The goal of this client is to handle the migration from redis to rabbit.
// All new incoming messages are routed to rabbitMQ, but redis client can still be used to retrieve older stream messages
// Once the oldest rabbitMQ stream is older than 1 month, we consider the redis stream outside of the TTL range and we switch to fully using the rabbitMQ client
let redisStreamFullyDeprecated = false;
const isRedisStreamFullyDeprecated = async (streamName = LIVE_STREAM_NAME, rabbitStreamInfo?: StreamInfo) => {
  if (redisStreamFullyDeprecated) {
    return redisStreamFullyDeprecated;
  }
  const completeRabbitStreamInfo = rabbitStreamInfo ?? await rabbitStreamClient.rawFetchStreamInfo(streamName);
  const redisStreamInfo = await redisStreamClient.rawFetchStreamInfo(streamName);
  const rabbitLastDate = utcDate(completeRabbitStreamInfo.firstEventDate);
  const oneMonthAgo = utcDate().subtract(1, 'month');
  redisStreamFullyDeprecated = redisStreamInfo.streamSize === 0 || rabbitLastDate.isBefore(oneMonthAgo);
  return redisStreamFullyDeprecated;
};

const initializeStreams = async () => {
  if (rabbitStreamClient.initializeStreams) {
    await rabbitStreamClient.initializeStreams();
  }
};

// region opencti data stream

const rawPushToStream = async <T extends BaseEvent> (event: T) => {
  await rabbitStreamClient.rawPushToStream<T>(event);
};

const rawFetchStreamInfo = async (streamName = LIVE_STREAM_NAME) => {
  const rabbitStreamInfo = await rabbitStreamClient.rawFetchStreamInfo(streamName);
  if (await isRedisStreamFullyDeprecated(streamName, rabbitStreamInfo)) {
    return rabbitStreamInfo;
  }
  // If redis stream is still not deprecated, we want to join it with rabbit stream info
  const redisStreamInfo = await redisStreamClient.rawFetchStreamInfo(streamName);
  return {
    lastEventId: redisStreamInfo.lastEventId,
    lastEventDate: redisStreamInfo.lastEventDate,
    firstEventId: rabbitStreamInfo.firstEventId,
    firstEventDate: rabbitStreamInfo.firstEventDate,
    streamSize: redisStreamInfo.streamSize + rabbitStreamInfo.streamSize,
  };
};

const rawCreateStreamProcessor = <T extends BaseEvent> (
  provider: string,
  callback: (events: Array<SseEvent<T>>, lastEventId: string) => Promise<void>,
  opts: StreamProcessorOption = {},
): StreamProcessor => {
  let isRabbitStreamProcessorActive = false;
  let redisLastEvendId: string;
  // eslint-disable-next-line prefer-const
  let redisStreamProcessor: StreamProcessor;
  // eslint-disable-next-line prefer-const
  let rabbitStreamProcessor: StreamProcessor;
  // We proxy the callback to handle the switch from using redis to using rabbit stream processor when we arrive at the end of the redis stream
  const proxyCallback = async (events: Array<SseEvent<T>>, lastEventId: string) => {
    await callback(events, lastEventId);
    if (!isRabbitStreamProcessorActive && lastEventId === redisLastEvendId) {
      // We can't call redisStreamProcessor shutdown in await:
      // doing so will be blocking indefinitely, since shutdown can't be processed because we are in current redis events process step
      redisStreamProcessor.shutdown().catch((e) => logApp.debug('Error during redis stream processor successful shutdown during rabbit switch', { e }));
      await rabbitStreamProcessor.start(lastEventId);
    }
  };

  redisStreamProcessor = redisStreamClient.rawCreateStreamProcessor<T>(provider, proxyCallback, opts);
  rabbitStreamProcessor = rabbitStreamClient.rawCreateStreamProcessor<T>(provider, proxyCallback, opts);

  const { streamName = LIVE_STREAM_NAME } = opts;
  return {
    info: async () => rawFetchStreamInfo(streamName),
    running: () => (isRabbitStreamProcessorActive ? rabbitStreamProcessor.running() : redisStreamProcessor.running()),
    start: async (start = 'live') => {
      // First case: start is live, we always route to using rabbit
      if (start === 'live') {
        isRabbitStreamProcessorActive = true;
        await rabbitStreamProcessor.start(start);
        // Second case: start is not live, but we consider rabbitMQ as the only available stream since it is older than 1 month
      } else if (await isRedisStreamFullyDeprecated(streamName)) {
        isRabbitStreamProcessorActive = true;
        await rabbitStreamProcessor.start(start);
      } else {
        // Third case: we need to check wether to start consuming in redis or rabbit.
        // We should start consuming in redis only if start is older than most recent redis message
        const startOffsetTime = start.split('-')[0];
        const redisStreamInfo = await redisStreamClient.rawFetchStreamInfo(streamName);
        const redisLastOffsetTime = redisStreamInfo.lastEventId.split('-')[0];
        redisLastEvendId = redisStreamInfo.lastEventId;
        if (startOffsetTime < redisLastOffsetTime) {
          isRabbitStreamProcessorActive = false;
          await redisStreamProcessor.start(start);
        } else {
          isRabbitStreamProcessorActive = true;
          await rabbitStreamProcessor.start(start);
        }
      }
    },
    shutdown: async () => {
      if (isRabbitStreamProcessorActive) {
        await rabbitStreamProcessor.shutdown();
      } else {
        await redisStreamProcessor.shutdown();
      }
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
  const { streamName } = opts;
  if (await isRedisStreamFullyDeprecated(streamName)) {
    return rabbitStreamClient.rawFetchStreamEventsRangeFromEventId(startEventId, callback, opts);
  }
  // If rabbit stream is still not older than 1 month, we have to potentially go through both redis & rabbit stream
  const { lastEventId } = await redisStreamClient.rawFetchStreamEventsRangeFromEventId(startEventId, callback, opts);
  const redisStreamInfo = await redisStreamClient.rawFetchStreamInfo();
  // If redis rawFetchStreamEventsRangeFromEventId went all the way to the last event stored in redis OR if it didn't move from request startEventI,
  // it means that we also need to request the data from rabbitMQ
  if (redisStreamInfo.firstEventId === lastEventId || redisStreamInfo.firstEventId === startEventId) {
    return rabbitStreamClient.rawFetchStreamEventsRangeFromEventId(startEventId, callback, opts);
  }
  return { lastEventId };
};

// region opencti notification stream
const rawStoreNotificationEvent = async <T extends StreamNotifEvent> (event: T) => {
  await rabbitStreamClient.rawStoreNotificationEvent<T>(event);
};
const rawFetchRangeNotifications = async <T extends StreamNotifEvent> (start: Date, end: Date): Promise<Array<T>> => {
  if (await isRedisStreamFullyDeprecated(NOTIFICATION_STREAM_NAME)) {
    return rabbitStreamClient.rawFetchRangeNotifications<T>(start, end);
  }
  // If reds stream is still not deprecated, we have to concatenate redis & rabbit stream data
  const redisRangeNotifications = await redisStreamClient.rawFetchRangeNotifications<T>(start, end);
  const rabbitRangeNotifications = await rabbitStreamClient.rawFetchRangeNotifications<T>(start, end);
  return [...redisRangeNotifications, ...rabbitRangeNotifications];
};
// endregion

// region opencti audit stream
const rawStoreActivityEvent = async (event: ActivityStreamEvent) => {
  await rabbitStreamClient.rawStoreActivityEvent(event);
};
// endregion

export const rawJoinedRedisRabbitStreamClient: RawStreamClient = {
  initializeStreams,
  rawPushToStream,
  rawFetchStreamInfo,
  rawCreateStreamProcessor,
  rawFetchStreamEventsRangeFromEventId,
  rawStoreNotificationEvent,
  rawFetchRangeNotifications,
  rawStoreActivityEvent,
};
