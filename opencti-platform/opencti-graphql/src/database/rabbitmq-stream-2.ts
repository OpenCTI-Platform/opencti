import util from 'util';
import { connect, Offset } from 'rabbitmq-stream-js-client';
import { amqpExecute, amqpHttpClient, send, streamConsumeQueue } from './rabbitmq';
import { RABBIT_QUEUE_PREFIX, wait } from './utils';
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
import type { AuthContext, AuthUser } from '../types/user';
import type { BaseEvent, DataEvent, SseEvent } from '../types/event';
import { logApp } from '../config/conf';
import { utcEpochTime } from '../utils/format';

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
        'x-stream-max-segment-size-bytes': 100000000 // max segment file size on disk, MUST BE SET AT QUEUE DECLARATION
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

const rawPushToStream = async (context: AuthContext, user:AuthUser, event: string[]) => {
  const client = await connect({
    vhost: '/',
    port: 5552,
    hostname: 'localhost',
    username: 'guest',
    password: 'guest'
  });
  const streamName = getRabbitMQStreamQueueName(LIVE_STREAM_NAME);
  const publisher = await client.declarePublisher({ stream: streamName });
  const rabbitMessage = buildStreamMessage(event);
  await publisher.send(Buffer.from(rabbitMessage));
  await client.close();
};
const rawFetchStreamInfo = async (streamName = LIVE_STREAM_NAME) => {
  const rabbitQueueName = getRabbitMQStreamQueueName(streamName);
  const httpClient = await amqpHttpClient();
  const streamData = await httpClient.get(`/api/queues/%2f/${rabbitQueueName}`).then((response) => response.data);
  const totalSize = streamData.messages;

  const client = await connect({
    vhost: '/',
    port: 5552,
    hostname: 'localhost',
    username: 'guest',
    password: 'guest'
  });

  // const meta = await client.queryMetadata({ streams: [rabbitQueueName] });
  // const d = await client.streamStatsRequest(rabbitQueueName);

  let lastMessage;
  const consumeMessage = (message: { content: { toString: () => any; }; }) => {
    lastMessage = message.content.toString();
  };
  await client.declareConsumer({ stream: rabbitQueueName, offset: Offset.first() }, consumeMessage);
  while (!lastMessage) {
    await wait(20);
  }
  await client.close();
  return { lastEventId: `${''}-0`, firstEventId: `${''}-0`, lastEventDate: '', firstEventDate: '', streamSize: totalSize };
};
const RETRY_CONNECTION_PERIOD = 10000;
const rawCreateStreamProcessor = <T extends BaseEvent> (
  provider: string,
  callback: (events: Array<SseEvent<T>>, lastEventId: string) => Promise<void>,
  opts: StreamOption = {}
): StreamProcessor => {
  const isRunning = true;
  let processingLoopPromise: Promise<void>;
  const { streamName = LIVE_STREAM_NAME, autoReconnect, withInternal } = opts;
  const rabbitQueueName = getRabbitMQStreamQueueName(streamName);
  let lastTimestamp: number;
  let currentTimestampCount = 0;

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
  const parseStreamMessage = async (message: string) => {
    const messageParsed = JSON.parse(message);
    const reconstructedStreamId = buildStreamId(messageParsed[0]);
    const reconstructedStreamEvent = [reconstructedStreamId, messageParsed[1]];
    await processStreamResult([reconstructedStreamEvent], callback, withInternal);
  };
  const queueConsumeCallback = async (message: string, ackCallback: () => void) => {
    await parseStreamMessage(message);
    ackCallback();
  };
  const handleStreamConsume = async (startEventId = 'live') => {
    let streamOffsetArg: string | { '!': string, value: number } = 'next';
    if (startEventId !== 'live') {
      let streamOffsetTime = '';
      [streamOffsetTime,] = startEventId.split('-');
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
      processingLoopPromise = (async () => { await handleStreamConsume(startEventId); })();
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
  const { streamName = LIVE_STREAM_NAME, withInternal } = opts;
  const rabbitQueueName = getRabbitMQStreamQueueName(streamName);

  const startEpochTime = Number(startEventId.split('-')[0]);
  let lastTimestamp = startEpochTime;
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
    const reconstructedStreamId = buildStreamId(messageTimestamp);
    const reconstructedStreamEvent = [reconstructedStreamId, messageParsed[1]];
    await processStreamResult([reconstructedStreamEvent], callback, withInternal);
    eventRetrievalTime = utcEpochTime();
    ackCallback();
  };
  const offsetInSeconds = startEpochTime / 1000;
  const streamOffsetArg = { '!': 'timestamp', value: offsetInSeconds };
  streamConsumeQueue(rabbitQueueName, connectionSetterCallback, queueConsumeCallback, { 'x-stream-offset': streamOffsetArg }).catch((e) => logApp.error('Could not retrieve stream event range data', { error: e }));

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

export const rawRabbitMQStreamClient2: RawStreamClient = {
  initializeStreams,
  rawPushToStream,
  rawFetchStreamInfo,
  rawCreateStreamProcessor,
  rawFetchStreamEventsRangeFromEventId,
  rawStoreNotificationEvent,
  rawFetchRangeNotifications,
  rawStoreActivityEvent,
};
