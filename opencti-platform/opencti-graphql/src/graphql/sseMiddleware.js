import * as R from 'ramda';
import * as bodyParser from 'body-parser';
import { basePath, logApp } from '../config/conf';
import { authenticateUser, STREAMAPI } from '../domain/user';
import { getStreamRange, createStreamProcessor } from '../database/redis';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { generateInternalId } from '../schema/identifier';
import { BYPASS } from '../schema/general';

let heartbeat;
const KEEP_ALIVE_INTERVAL_MS = 20000;
const broadcastClients = {};

const createBroadcastClient = (client) => {
  const broadcastClient = {
    client,
    sendEvent: (eventId, topic, event) => {
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
      if (isGrantedForData || isBypass) {
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
    const now = Date.now() / 1000;
    Object.values(broadcastClients)
      // Filter is required as the close is asynchronous
      .filter((c) => now < c.client.expirationTime)
      .forEach((c) => c.sendEvent(eventId, topic, data));
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

const createSeeMiddleware = (broadcaster) => {
  createHeartbeatProcessor();
  const eventsHandler = async (req, res) => {
    const client = {
      id: generateInternalId(),
      userId: req.userId,
      expirationTime: req.expirationTime,
      allowed_marking: req.allowed_marking,
      capabilities: req.capabilities,
      sendEvent: (id, topic, data) => {
        if (req.finished) {
          logApp.warn('[STREAM] Write on an already terminated response', { id: client.userId });
          return;
        }
        let message = '';
        if (id) {
          message += `id: ${id}\n`;
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
    broadcastClients[client.id] = broadcastClient;
    const clients = Object.entries(broadcastClients).length;
    const broadcasterInfo = await broadcaster.info();
    broadcastClient.sendConnected({ ...broadcasterInfo, connectionId: client.id, clients });
    logApp.debug(`[STREAM] Clients connection ${req.userId} (${clients})`);
  };
  return {
    shutdown: () => {
      clearInterval(heartbeat);
      Object.values(broadcastClients).forEach((c) => c.client.close());
      broadcaster.shutdown();
    },
    applyMiddleware: ({ app }) => {
      app.use(`${basePath}/stream`, authenticate);
      app.get(`${basePath}/stream`, eventsHandler);
      app.use(`${basePath}/stream/history`, bodyParser.json());
      app.post(`${basePath}/stream/history`, streamHistoryHandler);
    },
  };
};

export default createSeeMiddleware;
