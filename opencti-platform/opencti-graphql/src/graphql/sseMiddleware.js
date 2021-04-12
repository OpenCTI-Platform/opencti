import * as R from 'ramda';
import { basePath, logApp } from '../config/conf';
import { authenticateUser, computeAvailableMarkings, STREAMAPI, SYSTEM_USER } from '../domain/user';
import { createStreamProcessor } from '../database/redis';
import { ENTITY_TYPE_LABEL, ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { generateInternalId, generateStandardId, normalizeName } from '../schema/identifier';
import { BYPASS } from '../schema/general';
import { findById } from '../domain/stream';
import { EVENT_TYPE_UPDATE } from '../database/rabbitmq';
import { internalLoadById, stixLoadById } from '../database/middleware';
import { convertFiltersToQueryOptions } from '../domain/taxii';
import { elList } from '../database/elasticSearch';
import { READ_DATA_INDICES } from '../database/utils';
import { stixDataConverter } from '../database/stix';

let heartbeat;
const KEEP_ALIVE_INTERVAL_MS = 20000;
const broadcastClients = {};

const MARKING_FILTER = 'markedBy';
const LABEL_FILTER = 'labelledBy';
const CREATOR_FILTER = 'createdBy';
const TYPE_FILTER = 'entity_type';
const isEventMatchFilters = (event, filters) => {
  // User is granted but we still need to apply filters if needed
  const filterEntries = Object.entries(filters);
  if (filterEntries.length > 0) {
    return true;
  }
  for (let index = 0; index < filterEntries.length; index += 1) {
    const [type, values] = filterEntries[index];
    // --- Directly accessible in the event
    // Markings filtering
    if (type === MARKING_FILTER) {
      // event must have one of this marking
      const markingIds = values.map((v) => v.standard_id);
      const found = event.markings.length === 0 || event.markings.some((r) => markingIds.includes(r));
      if (!found) return false;
    }
    // --- Depending of the data
    // Entity type filtering
    const { data } = event;
    if (type === TYPE_FILTER) {
      const found = values.map((v) => v.id.toLowerCase()).includes(data.type);
      if (!found) return false;
    }
    // Creator filtering
    if (type === CREATOR_FILTER) {
      let dataCreator = data.created_by_ref;
      if (event.type === EVENT_TYPE_UPDATE) {
        dataCreator = data.x_data_update.add?.created_by_ref || data.x_data_update.remove?.created_by_ref;
      }
      const found = values.map((v) => v.id).includes(dataCreator);
      if (!found) return false;
    }
    // Labels filtering
    if (type === LABEL_FILTER) {
      const dataLabels = [];
      if (event.type === EVENT_TYPE_UPDATE) {
        dataLabels.push(...(data.x_data_update.add?.labels || []));
        dataLabels.push(...(data.x_data_update.remove?.labels || []));
      } else {
        dataLabels.push(...(data.labels || []));
      }
      const labelsIds = dataLabels.map((l) => generateStandardId(ENTITY_TYPE_LABEL, { value: normalizeName(l) }));
      const found = values.map((v) => v.id).some((r) => labelsIds.includes(r));
      if (!found) return false;
    }
  }
  return true;
};

const createBroadcastClient = (client) => {
  const broadcastClient = {
    client,
    isLiveClient: () => client.isLiveStream,
    sendEvent: (eventId, topic, event, filters = {}) => {
      const { data } = event;
      const clientMarkings = R.map((m) => m.standard_id, client.allowed_marking);
      const isMarkingObject = data.type === ENTITY_TYPE_MARKING_DEFINITION.toLowerCase();
      const isUserHaveAccess = event.markings.length === 0 || event.markings.every((m) => clientMarkings.includes(m));
      const isBypass = R.find((s) => s.name === BYPASS, client.capabilities || []) !== undefined;
      // Granted if:
      // - Event concern directly a marking definition
      // - Event has no specified markings
      // - User have all event markings
      // - User have the bypass capabilities
      const isGrantedForData = isMarkingObject || isUserHaveAccess;
      if (isBypass) {
        // If use have bypass, always push the event
        client.sendEvent(eventId, topic, event);
      } else if (isGrantedForData && isEventMatchFilters(event, filters)) {
        // Else if user granted and data is not filtered
        client.sendEvent(eventId, topic, event);
      }
      return true;
    },
    sendHeartbeat: () => {
      client.sendEvent(undefined, 'heartbeat', new Date());
    },
    sendConnected: (streamInfo) => {
      client.sendEvent(undefined, 'connected', streamInfo);
      broadcastClient.sendHeartbeat();
    },
  };
  return broadcastClient;
};

const createHeartbeatProcessor = () => {
  // Setup the heart beat
  heartbeat = setInterval(() => {
    const now = Date.now() / 1000;
    // Close expired sessions
    Object.values(broadcastClients)
      .filter((c) => now >= c.client.expirationTime)
      .forEach((c) => c.client.close());
    // Send heartbeat to alive sessions
    Object.values(broadcastClients)
      // Filter is required as the close is asynchronous
      .filter((c) => now < c.client.expirationTime)
      .forEach((c) => c.sendHeartbeat());
  }, KEEP_ALIVE_INTERVAL_MS);
};

export const initBroadcaster = () => {
  return createStreamProcessor(async (eventId, topic, data) => {
    let eventData = data;
    const now = Date.now() / 1000;
    // Determine if element need to be resolved
    const isLiveClientListening = broadcastClients.filter((b) => b.isLiveClient()).length > 0;
    if (isLiveClientListening) {
      // Live client need a resolved element
      // We can load with system user, element will be post filtered
      const instance = await stixLoadById(SYSTEM_USER, data.internal_id);
      eventData = { ...instance, ...data };
    }
    Object.values(broadcastClients)
      // Filter is required as the close is asynchronous
      .filter((c) => now < c.client.expirationTime)
      .forEach((c) => c.sendEvent(eventId, topic, eventData));
  });
};

export const broadcast = (event, data) => {
  Object.values(broadcastClients).forEach((broadcastClient) => {
    broadcastClient.sendEvent(event, data);
  });
};

const authenticate = async (req, res, next) => {
  const auth = await authenticateUser(req);
  const capabilityControl = (s) => s.name === BYPASS || s.name === STREAMAPI;
  const isUserGranted = auth && R.find(capabilityControl, auth.capabilities || []) !== undefined;
  if (isUserGranted) {
    req.userId = auth.id;
    req.capabilities = auth.capabilities;
    req.allowed_marking = auth.allowed_marking;
    req.expirationTime = new Date(2100, 10, 10); // auth.token.expirationTime;
    next();
  } else {
    res.status(401).json({ status: 'unauthorized' });
  }
};

/*
const streamHistoryHandler = async (req, res) => {
  const { userId, body } = req;
  const { from = '-', size = 200, connectionId } = body;
  const connectedClient = broadcastClients[connectionId];
  // Check if connection exist and the client is correctly related
  if (!connectedClient || connectedClient.client.userId !== userId) {
    res.status(401).json({ status: 'This stream connection does not exist' });
  } else {
    try {
      const rangeProcessor = (eventId, topic, data) =>
        connectedClient.sendEvent(eventId, topic, R.assoc('catchup', true, data));
      const streamRangeResult = await getStreamRange(from, size, rangeProcessor);
      res.json(streamRangeResult);
    } catch (e) {
      res.status(401).json({ status: e.message });
    }
  }
};
 */

const standardIdResolver = async (key, filters) => {
  // noinspection UnnecessaryLocalVariableJS
  const elements = await Promise.all(
    filters[key].map(async (f) => {
      const standardId = await internalLoadById(SYSTEM_USER, f.id).then((e) => e.standard_id);
      return { id: standardId, value: f.value };
    })
  );
  return elements;
};
const analyseFilters = async (req, filters = {}) => {
  const buildFilters = {};
  // If marking filters, we need to compute all possible markings
  if (filters[MARKING_FILTER]) {
    const all = req.session.user.all_marking;
    buildFilters[MARKING_FILTER] = computeAvailableMarkings(filters[MARKING_FILTER], all);
  }
  // If label filters, we need to resolve the standard ids
  if (filters[LABEL_FILTER]) {
    buildFilters[MARKING_FILTER] = await standardIdResolver(LABEL_FILTER, filters);
  }
  // If creator filters, we need to resolve the standard ids
  if (filters[CREATOR_FILTER]) {
    buildFilters[CREATOR_FILTER] = await standardIdResolver(CREATOR_FILTER, filters);
  }
  return buildFilters;
};

const createSeeMiddleware = (broadcaster) => {
  createHeartbeatProcessor();
  const createSseChannel = (req, res) => {
    const channel = {
      id: generateInternalId(),
      user: req.session.user,
      userId: req.userId,
      expirationTime: req.expirationTime,
      allowed_marking: req.allowed_marking,
      capabilities: req.capabilities,
      sendEvent: (eventId, topic, data) => {
        if (req.finished) {
          logApp.warn('[STREAM] Write on an already terminated response', { id: channel.userId });
          return;
        }
        let message = '';
        if (eventId) {
          message += `id: ${eventId}\n`;
        }
        if (topic) {
          message += `event: ${topic}\n`;
        }
        message += 'data: ';
        message += JSON.stringify(data);
        message += '\n\n';
        res.write(message);
        res.flush();
      },
      close: () => {
        channel.expirationTime = 0;
        try {
          res.end();
        } catch (e) {
          logApp.error('[STREAM] Failing to close client', { clientId: channel.userId, error: e });
        }
      },
    };
    return { channel, client: createBroadcastClient(channel) };
  };
  const streamHandler = async (req, res) => {
    const startFrom = req.query.from ? req.query.from : '0-0';
    const { channel, client } = createSseChannel(req, res);
    const processor = createStreamProcessor(async (eventId, topic, data) => {
      client.sendEvent(eventId, topic, data);
    }, startFrom);
    req.on('close', () => processor.shutdown());
    res.writeHead(200, {
      Connection: 'keep-alive',
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-cache, no-transform', // no-transform is required for dev proxy
    });
    const broadcasterInfo = await processor.info();
    channel.sendConnected({ ...broadcasterInfo, connectionId: client.id });
    await processor.start();
  };
  const filteredStreamHandler = async (req, res) => {
    const { id } = req.params;
    const startFrom = req.query.from;
    const connectionTime = new Date().getTime();
    const collection = await findById(req.session.user, id);
    const streamFilters = JSON.parse(collection.filters);
    const filters = await analyseFilters(req, streamFilters);
    const { channel, client } = createSseChannel(req, res);
    const processor = createStreamProcessor(async (eventId, topic, data) => {
      const [time] = eventId.split('-');
      const isLiveEvent = parseFloat(time) >= connectionTime;
      console.log(`${eventId} - ${isLiveEvent}`);
      client.sendEvent(eventId, topic, data, filters);
    }, startFrom || connectionTime);
    const broadcasterInfo = await processor.info();
    channel.sendConnected({ ...broadcasterInfo, connectionId: client.id });
    // If empty start date, stream all results corresponding to the filters
    if (R.isEmpty(startFrom)) {
      const queryOptions = convertFiltersToQueryOptions(streamFilters);
      const callback = async (elements) => {
        for (let index = 0; index < elements.length; index += 1) {
          const { internal_id: elemId } = elements[index];
          const instance = await stixLoadById(req.session.user, elemId);
          const data = stixDataConverter(instance, { diffMode: false });
          channel.sendEvent(instance.id, 'init', { data });
        }
      };
      queryOptions.minSource = true;
      queryOptions.callback = callback;
      await elList(req.session.user, READ_DATA_INDICES, queryOptions);
    }
    // After start to stream the live.
    await processor.start();
  };
  /*
  const eventsHandler = async (req, res) => {
    const { id } = req.params;
    // Could specified a collection
    const isLiveStream = !R.isEmpty(id) && !R.isNil(id);
    let streamFilters = {};
    let clientFilters = {};
    if (isLiveStream) {
      const collection = await findById(req.session.user, id);
      streamFilters = JSON.parse(collection.filters);
      clientFilters = await analyseFilters(req, streamFilters);
    }
    // Create client
    const client = {
      id: generateInternalId(),
      isLiveStream,
      filters: clientFilters,
      user: req.session.user,
      userId: req.userId,
      expirationTime: req.expirationTime,
      allowed_marking: req.allowed_marking,
      capabilities: req.capabilities,
      sendEvent: (eventId, topic, data) => {
        if (req.finished) {
          logApp.warn('[STREAM] Write on an already terminated response', { id: client.userId });
          return;
        }
        let message = '';
        if (eventId) {
          message += `id: ${eventId}\n`;
        }
        if (topic) {
          message += `event: ${topic}\n`;
        }
        message += 'data: ';
        message += JSON.stringify(data);
        message += '\n\n';
        res.write(message);
        res.flush();
      },
      close: () => {
        client.expirationTime = 0;
        try {
          res.end();
        } catch (e) {
          logApp.error('[STREAM] Failing to close client', { clientId: client.userId, error: e });
        }
      },
    };
    req.on('close', () => {
      if (client === broadcastClients[client.id]?.client) {
        delete broadcastClients[client.id];
      }
    });
    res.writeHead(200, {
      Connection: 'keep-alive',
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-cache, no-transform', // no-transform is required for dev proxy
    });
    // Create the new connection
    const broadcastClient = createBroadcastClient(client);
    const clients = Object.entries(broadcastClients).length;
    const broadcasterInfo = await broadcaster.info();
    broadcastClient.sendConnected({ ...broadcasterInfo, connectionId: client.id, clients });
    logApp.debug(`[STREAM] Clients connection ${req.userId} (${clients})`);
    // If live stream, need to send the initial data
    if (!R.isEmpty(streamFilters)) {
      const queryOptions = convertFiltersToQueryOptions(streamFilters, null);
      const callback = async (elements) => {
        for (let index = 0; index < elements.length; index += 1) {
          const { internal_id: elemId } = elements[index];
          const instance = await stixLoadById(req.session.user, elemId);
          const data = stixDataConverter(instance, { diffMode: false });
          client.sendEvent(null, 'catchup', { data });
        }
      };
      queryOptions.minSource = true;
      queryOptions.callback = callback;
      await elList(req.session.user, READ_DATA_INDICES, queryOptions);
    }
    // Register the new client
    broadcastClients[client.id] = broadcastClient;
  };
  */
  return {
    shutdown: () => {
      clearInterval(heartbeat);
      Object.values(broadcastClients).forEach((c) => c.client.close());
      broadcaster.shutdown();
    },
    applyMiddleware: ({ app }) => {
      app.use(`${basePath}/stream`, authenticate);
      app.get(`${basePath}/stream`, streamHandler);
      app.get(`${basePath}/stream/:id`, filteredStreamHandler);
      // app.use(`${basePath}/stream/history`, bodyParser.json());
      // app.post(`${basePath}/stream/history`, streamHistoryHandler);
    },
  };
};

export default createSeeMiddleware;
