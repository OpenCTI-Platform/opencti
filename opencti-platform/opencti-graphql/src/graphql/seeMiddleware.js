import * as R from 'ramda';
import * as bodyParser from 'body-parser';
import { logger, OPENCTI_TOKEN } from '../config/conf';
import { authentication } from '../domain/user';
import { extractTokenFromBearer } from './graphql';
import { generateInternalId } from '../schema/identifier';
import { catchup, listenStream } from '../database/redis';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';

let heartbeat;
const KEEP_ALIVE_INTERVAL_MS = 20000;
const broadcastClients = {};

const createBroadcastClient = (client) => {
  const broadcastClient = {
    client,
    catchingUp: true,
    sendEvent: (eventId, topic, event) => {
      const { data } = event;
      const clientMarkings = R.map((m) => m.standard_id, client.allowed_marking);
      const isMarking = data.type === ENTITY_TYPE_MARKING_DEFINITION.toLowerCase();
      const isUserHaveAccess = event.markings.length > 0 && event.markings.every((m) => clientMarkings.includes(m));
      const granted = isMarking || isUserHaveAccess;
      const accessData = Object.assign(event, { granted });
      if (granted) {
        client.sendEvent(eventId, topic, accessData);
      } else {
        const filteredData = R.pick(['markings', 'timestamp', 'granted'], accessData);
        client.sendEvent(eventId, topic, filteredData);
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

export const initBroadcaster = async () => {
  // Listen the stream from now
  // noinspection JSIgnoredPromiseFromCall
  const stream = await listenStream((eventId, topic, data) => {
    const now = Date.now() / 1000;
    Object.values(broadcastClients)
      // Filter is required as the close is asynchronous
      .filter((c) => now < c.client.expirationTime)
      .forEach((c) => c.sendEvent(eventId, topic, data));
  });
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
  return stream;
};

export const broadcast = (event, data) => {
  Object.values(broadcastClients).forEach((broadcastClient) => {
    broadcastClient.sendEvent(event, data);
  });
};

const authenticate = async (req, res, next) => {
  let token = req.cookies ? req.cookies[OPENCTI_TOKEN] : null;
  token = token || extractTokenFromBearer(req.headers.authorization);
  const auth = await authentication(token);
  if (auth) {
    req.userId = auth.id;
    req.allowed_marking = auth.allowed_marking;
    req.expirationTime = new Date(2100, 10, 10); // auth.token.expirationTime;
    next();
  } else {
    res.status(401).json({ status: 'unauthorized' });
  }
};

const catchupHandler = async (req, res) => {
  const { userId, body } = req;
  const clients = Object.entries(broadcastClients);
  const connectedClient = R.find(([, data]) => {
    return data.client.userId === userId;
  }, clients);
  if (!connectedClient) {
    res.status(401).json({ status: 'User stream not connected' });
  } else {
    const { from = '-', size = 50 } = body;
    const broadcastClient = R.last(connectedClient);
    try {
      await catchup(from, size, (eventId, topic, data) => {
        broadcastClient.sendEvent(eventId, topic, data);
      });
      res.json({ success: true });
    } catch (e) {
      res.json({ success: false, error: e.message });
    }
  }
};

const createSeeMiddleware = (broadcaster) => {
  const eventsHandler = (req, res) => {
    const clientId = generateInternalId();
    const client = {
      id: clientId,
      userId: req.userId,
      expirationTime: req.expirationTime,
      allowed_marking: req.allowed_marking,
      sendEvent: (id, topic, data) => {
        if (req.finished) {
          logger.info('Trying to write on an already terminated response', { id: client.id });
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
          logger.error(e, 'Failing to close client', { clientId: client.id });
        }
      },
    };
    req.on('close', () => {
      Object.values(broadcastClients)
        .filter((c) => c.client.userId === req.userId)
        .forEach((c) => c.client.close());
      delete broadcastClients[client.id];
    });
    res.writeHead(200, {
      Connection: 'keep-alive',
      'Content-Type': 'text/event-stream',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-cache, no-transform', // no-transform is required for dev proxy
    });
    const broadcastClient = createBroadcastClient(client);
    broadcastClient.sendConnected(broadcaster.info());
    broadcastClients[client.id] = broadcastClient;
    logger.info('[STREAM] > New client connected', { userId: req.userId });
  };
  return {
    shutdown: () => {
      broadcaster.shutdown();
      clearInterval(heartbeat);
      Object.values(broadcastClients).forEach((c) => c.client.close());
    },
    applyMiddleware: ({ app }) => {
      app.use('/stream', authenticate);
      app.get('/stream', eventsHandler);
      app.use('/stream/catchup', bodyParser.json());
      app.post('/stream/catchup', catchupHandler);
    },
  };
};

export default createSeeMiddleware;
