import { logger, OPENCTI_TOKEN } from '../config/conf';
import { authentication } from '../domain/user';
import { extractTokenFromBearer } from './graphql';
import { generateInternalId } from '../schema/identifier';
import { listenStream } from '../database/redis';

let heartbeat;
const KEEP_ALIVE_INTERVAL_MS = 20000;
const broadcastClients = {};

const createBroadcastClient = (client) => {
  const broadcastClient = {
    client,
    catchingUp: true,
    sendEvent: (eventId, topic, data) => {
      const { communities } = client;
      const { markings } = data;
      // TODO check markings in regards of communities
      client.sendEvent(eventId, topic, data);
      return true;
    },
    sendHeartbeat: () => {
      client.sendEvent(undefined, 'heartbeat', new Date());
    },
    sendConnected: () => {
      client.sendEvent(undefined, 'connected', 'connected');
      broadcastClient.sendHeartbeat();
    },
  };
  return broadcastClient;
};

const initBroadcaster = async () => {
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
    req.expirationTime = new Date(2100, 10, 10); // auth.token.expirationTime;
    next();
  } else {
    res.status(401).json({ status: 'unauthorized' });
  }
};

const createSeeMiddleware = () => {
  let streamListener;
  initBroadcaster().then((stream) => {
    streamListener = stream;
  });
  const eventsHandler = (req, res) => {
    const clientId = generateInternalId();
    const client = {
      id: clientId,
      userId: req.userId,
      expirationTime: req.expirationTime,
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
        .filter((c) => c.client.id === req.userId)
        .forEach((c) => c.client.close());
    });
    res.writeHead(200, {
      Connection: 'keep-alive',
      'Content-Type': 'text/event-stream',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-cache, no-transform', // no-transform is required for dev proxy
    });
    const broadcastClient = createBroadcastClient(client);
    broadcastClient.sendConnected();
    broadcastClients[client.id] = broadcastClient;
  };
  return {
    shutdown: () => {
      streamListener.shutdown();
      clearInterval(heartbeat);
      Object.values(broadcastClients).forEach((c) => c.client.close());
    },
    applyMiddleware: ({ app }) => {
      app.use('/stream', authenticate);
      app.get('/stream', eventsHandler);
    },
  };
};

export default createSeeMiddleware;
