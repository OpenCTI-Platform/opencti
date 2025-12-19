import util from 'util';
import { SEMATTRS_DB_NAME } from '@opentelemetry/semantic-conventions';
import { amqpExecute, amqpHttpClient, send, streamConsumeQueue } from './rabbitmq';
import { RABBIT_QUEUE_PREFIX, wait } from './utils';
import { ACTIVITY_STREAM_NAME, LIVE_STREAM_NAME, NOTIFICATION_STREAM_NAME, type RawStreamClient, type StreamProcessor } from './stream/stream-utils';
import { telemetry } from '../config/tracing';
import type { AuthContext, AuthUser } from '../types/user';
import type { BaseEvent, DataEvent, SseEvent } from '../types/event';
import { logApp } from '../config/conf';
import { utcDate, utcEpochTime } from '../utils/format';

export const STREAM_EXCHANGE = `${RABBIT_QUEUE_PREFIX}amqp.stream.exchange`;
export const streamRouting = (streamName = LIVE_STREAM_NAME) => `${RABBIT_QUEUE_PREFIX}stream_routing_${streamName}`;

const getRabbitMQStreamQueueName = (streamName: string) => {
  return `${RABBIT_QUEUE_PREFIX}stream_${streamName}`;
};
const buildStreamMessage = (event: string[]) => {
  const currentTime = utcEpochTime();
  const fullStreamData = [currentTime, event];
  return JSON.stringify(fullStreamData);
};

// STREAMS DOC https://www.rabbitmq.com/docs/streams
const registerStreamQueue = async (streamName: string) => {
  const streamQueue = getRabbitMQStreamQueueName(streamName);
  await amqpExecute(async (channel: any) => {
    // 01. Ensure exchange exists
    const assertExchange = util.promisify(channel.assertExchange).bind(channel);
    await assertExchange(STREAM_EXCHANGE, 'direct', { durable: true });
    // 02. Ensure listen queue exists
    const assertStreamQueue = util.promisify(channel.assertQueue).bind(channel);
    await assertStreamQueue(streamQueue, {
      exclusive: false,
      durable: true,
      autoDelete: false,
      arguments: {
        name: streamName,
        'x-queue-type': 'stream',
        'x-max-length-bytes': 20000000000, // in bytes, can be declared as policy (?)
        'x-max-age': '1M', // valid units: Y, M, D, h, m, s, can be declared as policy (?)
        'x-stream-max-segment-size-bytes': 100000000, // max segment file size on disk, MUST BE SET AT QUEUE DECLARATION
      },
    });
    // 03. bind queue for each connector scope
    const bindQueue = util.promisify(channel.bindQueue).bind(channel);
    await bindQueue(streamQueue, STREAM_EXCHANGE, streamRouting(streamName), {});
    return true;
  });
};

const initializeStreams = async () => {
  await registerStreamQueue(LIVE_STREAM_NAME);
  await registerStreamQueue(NOTIFICATION_STREAM_NAME);
  await registerStreamQueue(ACTIVITY_STREAM_NAME);
};

const rawPushToStream = async (context: AuthContext, user: AuthUser, event: string[]) => {
  const routingKey = streamRouting(LIVE_STREAM_NAME);
  const rabbitMessage = buildStreamMessage(event);
  const pushToStreamFn = async () => {
    await send(STREAM_EXCHANGE, routingKey, rabbitMessage);
  };
  await telemetry(context, user, 'INSERT STREAM', {
    [SEMATTRS_DB_NAME]: 'stream_engine',
  }, pushToStreamFn);
};
const rawFetchStreamInfo = async (streamName = LIVE_STREAM_NAME) => {
  const rabbitQueueName = getRabbitMQStreamQueueName(streamName);
  const httpClient = await amqpHttpClient();
  const streamData = await httpClient.get(`/api/queues/%2f/${rabbitQueueName}`).then((response) => response.data);
  const totalSize = streamData.messages;

  let lastEventTimestamp: number = -1;
  let rabbitMqFirstConnection: { close: () => void };
  const connectionSetterFirstCallback = (conn: any) => {
    rabbitMqFirstConnection = conn;
  };
  const queueConsumeFirstCallback = (data: string) => {
    [lastEventTimestamp] = JSON.parse(data);
    rabbitMqFirstConnection.close();
  };
  streamConsumeQueue(rabbitQueueName, connectionSetterFirstCallback, queueConsumeFirstCallback, { 'x-stream-offset': 'first' }).catch((e) => logApp.error('Could not retrieve stream first info', { error: e }));

  let firstEventTimestamp = -1;
  let firstEventRetrievalTime = -1;
  let rabbitMqLastConnection: { close: () => void } = { close: () => {} };
  const connectionSetterLastCallback = (conn: any) => {
    rabbitMqLastConnection = conn;
  };
  const queueConsumeLastCallback = (data: string, ackCallback: () => void) => {
    [firstEventTimestamp] = JSON.parse(data);
    firstEventRetrievalTime = utcEpochTime();
    ackCallback();
  };
  streamConsumeQueue(rabbitQueueName, connectionSetterLastCallback, queueConsumeLastCallback, { 'x-stream-offset': 'last' }).catch((e) => logApp.error('Could not retrieve stream last info', { error: e }));

  // because last streamoffset doesn't give last message but last chunk, we have to iterate over the last chunk messages to get the last message
  // we consider the last chunk received when there hasn't been any last message received for 100ms
  // TODO improve end of stream detection? currently 100 is very arbitrary
  while (lastEventTimestamp < 0 || firstEventRetrievalTime < 0 || (utcEpochTime() - firstEventRetrievalTime) < 100) {
    await wait(5);
  }
  rabbitMqLastConnection.close();
  const lastEventDate = utcDate(lastEventTimestamp).toISOString();
  const firstEventDate = utcDate(firstEventTimestamp).toISOString();
  return { lastEventId: `${lastEventTimestamp}-0`, firstEventId: `${firstEventTimestamp}-0`, firstEventDate, lastEventDate, streamSize: totalSize };
};
const RETRY_CONNECTION_PERIOD = 10000;
const rawCreateStreamProcessor = <T extends BaseEvent> (
  provider: string,
  callback: (events: Array<SseEvent<T>>, lastEventId: string) => Promise<void>,
  opts: StreamOption = {},
): StreamProcessor => {
  const isRunning = true;
  let processingLoopPromise: Promise<void>;
  const { streamName = LIVE_STREAM_NAME, autoReconnect, withInternal } = opts;
  const rabbitQueueName = getRabbitMQStreamQueueName(streamName);
  let lastTimestamp: number;
  let currentTimestampCount = 0;
  let stertStreamOffsetTime: number;

  let rabbitMqConnection: { close: () => void };
  const connectionSetterCallback = (conn: any) => {
    rabbitMqConnection = conn;
  };
  const buildStreamId = (messageTimestamp: number) => {
    // because timestamps stored in rabbitmq might not be ordered properly (timestamps are computed in nodeJS when sending
    if (lastTimestamp && messageTimestamp <= lastTimestamp) {
      currentTimestampCount += 1;
    } else {
      currentTimestampCount = 0;
      lastTimestamp = messageTimestamp;
    }
    return `${lastTimestamp}-${currentTimestampCount}`;
  };
  const queueConsumeCallback = async (message: string, ackCallback: () => void) => {
    const messageParsed = JSON.parse(message);
    const messageTimestamp = messageParsed[0];
    if (messageTimestamp < stertStreamOffsetTime) {
      ackCallback();
      return;
    }
    const reconstructedStreamId = buildStreamId(messageTimestamp);
    const reconstructedStreamEvent = [reconstructedStreamId, messageParsed[1]];
    await processStreamResult([reconstructedStreamEvent], callback, withInternal);
    ackCallback();
  };
  const handleStreamConsume = async (startEventId = 'live') => {
    let streamOffsetArg: string | { '!': string; value: number } = 'next';
    if (startEventId !== 'live') {
      let streamOffsetTime = '';
      [streamOffsetTime] = startEventId.split('-');
      stertStreamOffsetTime = Number(streamOffsetTime);
      const offsetInSeconds = streamOffsetTime.slice(0, -3);
      streamOffsetArg = { '!': 'timestamp', value: Number(offsetInSeconds) };
    }
    streamConsumeQueue(rabbitQueueName, connectionSetterCallback, queueConsumeCallback, { 'x-stream-offset': streamOffsetArg }).catch(() => {
      if (rabbitMqConnection) {
        try {
          rabbitMqConnection.close();
        } catch (e) {
          logApp.error('Closing RabbitMQ connection failed', { cause: e });
        }
      }
      if (autoReconnect) {
        setTimeout(handleStreamConsume as unknown as (args: void) => void, RETRY_CONNECTION_PERIOD);
      }
    });
  };
  return {
    info: async () => rawFetchStreamInfo(streamName),
    running: () => isRunning,
    start: async (startEventId = 'live') => {
      logApp.info('[STREAM] Starting queue consuming', { provider, startEventId });
      processingLoopPromise = (async () => {
        await handleStreamConsume(startEventId);
      })();
    },
    shutdown: async () => {
      logApp.info('[STREAM] Shutdown rabbit connection', { provider });
      rabbitMqConnection?.close();
      if (processingLoopPromise) {
        await processingLoopPromise;
      }
    },
  };
};
const rawFetchStreamEventsRangeFromEventId = async (
  startEventId: string,
  callback: (events: Array<SseEvent<DataEvent>>, lastEventId: string) => void,
  opts: StreamOption = {},
) => {
  const { streamName = LIVE_STREAM_NAME, withInternal, streamBatchSize = 100 } = opts;
  const rabbitQueueName = getRabbitMQStreamQueueName(streamName);

  const startEpochTimeString = startEventId.split('-')[0];
  const startEpochTime = Number(startEpochTimeString);
  let lastTimestamp = startEpochTime;
  let currentTimestampCount = 0;
  let eventRetrievalTime = -1;
  let totalCount = 0;

  let rabbitMqConnection: { close: () => void } = { close: () => {} };
  const connectionSetterCallback = (conn: any) => {
    rabbitMqConnection = conn;
  };
  const buildStreamId = (messageTimestamp: number) => {
    // because timestamps stored in rabbitmq might not be ordered properly (timestamps are computed in nodeJS when sending
    if (lastTimestamp && messageTimestamp <= lastTimestamp) {
      currentTimestampCount += 1;
    } else {
      currentTimestampCount = 0;
      lastTimestamp = messageTimestamp;
    }
    return `${lastTimestamp}-${currentTimestampCount}`;
  };
  const queueConsumeCallback = async (message: string, ackCallback: () => void) => {
    const messageParsed = JSON.parse(message);
    const messageTimestamp = messageParsed[0];
    if (messageTimestamp < startEpochTime) {
      ackCallback();
      return;
    }
    if (totalCount > streamBatchSize) {
      rabbitMqConnection.close();
      return;
    }
    const reconstructedStreamId = buildStreamId(messageTimestamp);
    const reconstructedStreamEvent = [reconstructedStreamId, messageParsed[1]];
    await processStreamResult([reconstructedStreamEvent], callback, withInternal);
    eventRetrievalTime = utcEpochTime();
    totalCount += 1;
    ackCallback();
  };
  const offsetInSeconds = startEpochTimeString.slice(0, -3);
  const streamOffsetArg = { '!': 'timestamp', value: offsetInSeconds };
  streamConsumeQueue(rabbitQueueName, connectionSetterCallback, queueConsumeCallback, { 'x-stream-offset': streamOffsetArg }).catch((e) => logApp.error('Could not retrieve stream event range data', { error: e, streamOffsetArg }));

  // TODO improve end of stream detection? currently 100 is very arbitrary
  while (eventRetrievalTime < 0 || (utcEpochTime() - eventRetrievalTime) < 100) {
    await wait(5);
  }
  rabbitMqConnection.close();
  return { lastEventId: `${lastTimestamp}-${currentTimestampCount}` };
};
const rawStoreNotificationEvent = async (event: string[]) => {
  const routingKey = streamRouting(NOTIFICATION_STREAM_NAME);
  const rabbitMessage = buildStreamMessage(event);
  await send(STREAM_EXCHANGE, routingKey, rabbitMessage);
};
const rawFetchRangeNotifications = async <T extends BaseEvent> (start: Date, end: Date): Promise<Array<T>> => {
  const rabbitQueueName = getRabbitMQStreamQueueName(NOTIFICATION_STREAM_NAME);

  const rangeNotifications: Array<T> = [];
  const startEpochTime = utcEpochTime(start as any);
  const endEpochTime = utcEpochTime(end as any);
  let lastTimestamp: number;
  let currentTimestampCount = 0;
  let eventRetrievalTime = -1;

  let rabbitMqConnection: { close: () => void } = { close: () => {} };
  const connectionSetterCallback = (conn: any) => {
    rabbitMqConnection = conn;
  };
  const buildStreamId = (messageTimestamp: number) => {
    // because timestamps stored in rabbitmq might not be ordered properly (timestamps are computed in nodeJS when sending
    if (lastTimestamp && messageTimestamp <= lastTimestamp) {
      currentTimestampCount += 1;
    } else {
      currentTimestampCount = 0;
      lastTimestamp = messageTimestamp;
    }
    return `${lastTimestamp}-${currentTimestampCount}`;
  };
  const queueConsumeCallback = async (message: string, ackCallback: () => void) => {
    const messageParsed = JSON.parse(message);
    const messageTimestamp = messageParsed[0];
    if (messageTimestamp < startEpochTime) {
      ackCallback();
      return;
    }
    if (messageTimestamp > endEpochTime) {
      return;
    }
    const reconstructedStreamId = buildStreamId(messageTimestamp);
    const reconstructedStreamEvent = [reconstructedStreamId, messageParsed[1]];
    const eventData = mapStreamToJS(reconstructedStreamEvent);
    if (eventData.event === 'live') {
      rangeNotifications.push(eventData.data);
    }
    eventRetrievalTime = utcEpochTime();
    ackCallback();
  };
  const offsetInSeconds = startEpochTime / 1000;
  const streamOffsetArg = { '!': 'timestamp', value: offsetInSeconds };
  streamConsumeQueue(rabbitQueueName, connectionSetterCallback, queueConsumeCallback, { 'x-stream-offset': streamOffsetArg }).catch((e) => logApp.error('Could not retrieve notification stream data', { error: e }));

  // TODO improve end of stream detection? currently 100 is very arbitrary
  while (eventRetrievalTime < 0 || (utcEpochTime() - eventRetrievalTime) < 100) {
    await wait(5);
  }
  rabbitMqConnection.close();
  return rangeNotifications;
};
const rawStoreActivityEvent = async (event: string[]) => {
  const routingKey = streamRouting(ACTIVITY_STREAM_NAME);
  const rabbitMessage = buildStreamMessage(event);
  await send(STREAM_EXCHANGE, routingKey, rabbitMessage);
};

export const rawRabbitMQStreamClient: RawStreamClient = {
  initializeStreams,
  rawPushToStream,
  rawFetchStreamInfo,
  rawCreateStreamProcessor,
  rawFetchStreamEventsRangeFromEventId,
  rawStoreNotificationEvent,
  rawFetchRangeNotifications,
  rawStoreActivityEvent,
};
