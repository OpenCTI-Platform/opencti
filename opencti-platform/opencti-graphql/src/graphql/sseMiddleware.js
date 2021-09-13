import * as R from 'ramda';
import { Promise } from 'bluebird';
import { basePath, logApp } from '../config/conf';
import { authenticateUserFromRequest, STREAMAPI } from '../domain/user';
import { createStreamProcessor } from '../database/redis';
import { generateInternalId, generateStandardId } from '../schema/identifier';
import { findById } from '../domain/stream';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE } from '../database/rabbitmq';
import { stixDataById, stixLoadById } from '../database/middleware';
import { convertFiltersToQueryOptions } from '../domain/taxii';
import { elList, ES_MAX_CONCURRENCY } from '../database/elasticSearch';
import {
  generateCreateMessage,
  isNotEmptyField,
  READ_INDEX_STIX_CORE_RELATIONSHIPS,
  READ_INDEX_STIX_CYBER_OBSERVABLES,
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_INDEX_STIX_META_OBJECTS,
  READ_INDEX_STIX_SIGHTING_RELATIONSHIPS,
} from '../database/utils';
import { buildStixData } from '../database/stix';
import { BYPASS, isBypassUser } from '../utils/access';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { FROM_START_STR, utcDate } from '../utils/format';
import { stixRefsExtractor } from '../schema/stixEmbeddedRelationship';

let heartbeat;
const STREAM_EVENT_VERSION = 3;
export const MIN_LIVE_STREAM_EVENT_VERSION = 2;
const KEEP_ALIVE_INTERVAL_MS = 20000;
const broadcastClients = {};

const isEventGranted = (event, user) => {
  const { data } = event;
  // Granted if:
  // - Event concern directly a marking definition
  // - Event has no specified markings
  // - User have all event markings
  // - User have the bypass capabilities
  const clientMarkings = R.flatten(R.map((m) => [m.standard_id, m.internal_id], user.allowed_marking));
  const isMarkingObject = data.type === ENTITY_TYPE_MARKING_DEFINITION.toLowerCase();
  const isUserHaveAccess =
    (event.markings || []).length === 0 || event.markings.every((m) => clientMarkings.includes(m));
  const isBypass = isBypassUser(user);
  const isGrantedForData = isMarkingObject || isUserHaveAccess;
  return isBypass || isGrantedForData;
};

const createBroadcastClient = (channel) => {
  return {
    id: channel.id,
    userId: channel.userId,
    expirationTime: channel.expirationTime,
    setChannelDelay: (d) => channel.setDelay(d),
    close: () => channel.close(),
    sendEvent: (eventId, topic, event) => {
      // Send event only if user is granted for
      if (isEventGranted(event, channel)) {
        channel.sendEvent(eventId, topic, event);
      }
    },
    sendHeartbeat: () => {
      channel.sendEvent(undefined, 'heartbeat', new Date());
    },
    sendConnected: (streamInfo) => {
      channel.sendEvent(undefined, 'connected', streamInfo);
    },
  };
};

const createHeartbeatProcessor = () => {
  // Setup the heart beat
  heartbeat = setInterval(() => {
    const now = Date.now() / 1000;
    // Close expired sessions
    Object.values(broadcastClients)
      .filter((c) => now >= c.expirationTime)
      .forEach((c) => c.close());
    // Send heartbeat to alive sessions
    Object.values(broadcastClients)
      // Filter is required as the close is asynchronous
      .filter((c) => now < c.expirationTime)
      .forEach((c) => c.sendHeartbeat());
  }, KEEP_ALIVE_INTERVAL_MS);
};

const authenticate = async (req, res, next) => {
  try {
    const auth = await authenticateUserFromRequest(req);
    const capabilityControl = (s) => s.name === BYPASS || s.name === STREAMAPI;
    const isUserGranted = auth && R.find(capabilityControl, auth.capabilities || []) !== undefined;
    if (isUserGranted) {
      req.userId = auth.id;
      req.capabilities = auth.capabilities;
      req.allowed_marking = auth.allowed_marking;
      req.expirationTime = utcDate().add(1, 'days').toDate();
      next();
    } else {
      res.statusMessage = 'You are not authenticated, please check your credentials';
      res.status(401).end();
    }
  } catch (err) {
    res.statusMessage = `Error in stream: ${err.message}`;
    res.status(500).end();
  }
};

const createSeeMiddleware = () => {
  const queryIndices = [
    READ_INDEX_STIX_DOMAIN_OBJECTS, // Malware, ...
    READ_INDEX_STIX_META_OBJECTS, // Marking def, External ref ...
    READ_INDEX_STIX_CYBER_OBSERVABLES, // File, ...
    READ_INDEX_STIX_CORE_RELATIONSHIPS, // related-to, ...
    READ_INDEX_STIX_SIGHTING_RELATIONSHIPS, // sighting, ...
  ];
  createHeartbeatProcessor();
  const wait = (ms) => {
    return new Promise((resolve) => setTimeout(resolve, ms));
  };
  const resolveMissingReferences = async (req, streamFilters, startingDate, afterDate, missingRefs, publishCache) => {
    const refsToResolve = missingRefs.filter((m) => !publishCache.has(m));
    const missingElements = [];
    if (refsToResolve.length > 0) {
      const missingOptions = convertFiltersToQueryOptions(streamFilters, { field: 'updated_at', after: afterDate });
      missingOptions.filters.push({ key: 'created_at', values: [startingDate], operator: 'gte' });
      const idsOpts = { ids: refsToResolve, ...missingOptions, connectionFormat: false };
      const findMissing = await elList(req.session.user, queryIndices, idsOpts);
      const missingIds = R.uniq(findMissing.map((f) => f.standard_id));
      missingElements.push(...missingIds);
      // eslint-disable-next-line prettier/prettier
      const resolvedElements = await Promise.map(missingIds, (id) => stixDataById(req.session.user, id), { concurrency: ES_MAX_CONCURRENCY });
      const parentRefs = resolvedElements.map((r) => stixRefsExtractor(r, generateStandardId)).flat();
      if (parentRefs.length > 0) {
        // eslint-disable-next-line prettier/prettier
        const newMissing = await resolveMissingReferences(req, streamFilters, startingDate, afterDate, parentRefs, publishCache);
        missingElements.unshift(...newMissing);
      }
    }
    return missingElements;
  };
  const initBroadcasting = async (req, res, client, processor = null) => {
    const broadcasterInfo = processor ? await processor.info() : {};
    req.on('close', () => {
      req.finished = true;
      delete broadcastClients[client.id];
      if (processor) {
        processor.shutdown();
      }
    });
    res.writeHead(200, {
      Connection: 'keep-alive',
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-cache, no-transform', // no-transform is required for dev proxy
    });
    client.sendConnected({ ...broadcasterInfo, connectionId: client.id });
    broadcastClients[client.id] = client;
  };
  const createSseChannel = (req, res) => {
    const channel = {
      id: generateInternalId(),
      delay: parseInt(req.query.delay || req.headers['event-delay'] || 10, 10),
      user: req.session.user,
      userId: req.userId,
      expirationTime: req.expirationTime,
      allowed_marking: req.allowed_marking,
      capabilities: req.capabilities,
      setDelay: (d) => {
        channel.delay = d;
      },
      connected: () => !req.finished,
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
        if (data) {
          message += 'data: ';
          message += JSON.stringify(data);
          message += '\n';
        }
        message += '\n';
        res.write(message);
        res.flush();
      },
      close: () => {
        logApp.info('[STREAM] Closing SSE channel', { clientId: channel.userId });
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
  const genericStreamHandler = async (req, res) => {
    try {
      const { client } = createSseChannel(req, res);
      const processor = createStreamProcessor(req.session.user, req.session.user.user_email, async (elements) => {
        for (let index = 0; index < elements.length; index += 1) {
          const { id: eventId, topic, data } = elements[index];
          client.sendEvent(eventId, topic, data);
        }
      });
      await initBroadcasting(req, res, client, processor);
      const lastEventId = req.query.from || req.headers['last-event-id'];
      await processor.start(lastEventId);
    } catch (err) {
      res.statusMessage = `Error in stream: ${err.message}`;
      res.status(500).end();
    }
  };
  const manageStreamConnectionHandler = async (req, res) => {
    try {
      const { id } = req.params;
      const client = broadcastClients[id];
      if (client) {
        if (client.userId !== req.session.user.id) {
          res.statusMessage = 'You cant access this resource';
          res.status(401).end();
        } else {
          const { delay = 10 } = req.body;
          client.setChannelDelay(delay);
          res.json({ message: 'ok' });
        }
      } else {
        res.statusMessage = 'This is not your connection';
        res.status(401).end();
      }
    } catch (err) {
      res.statusMessage = `Error in connection management: ${err.message}`;
      res.status(500).end();
    }
  };
  const filteredStreamHandler = async (req, res) => {
    try {
      const { id } = req.params;
      const version = STREAM_EVENT_VERSION;
      const startFrom = req.query.from || req.headers['last-event-id'];
      const listenDelete = (req.query['listen-delete'] || req.headers['listen-delete']) === 'true';
      let streamFilters = {};
      if (id !== 'live') {
        const collection = await findById(req.session.user, id);
        if (!collection) {
          res.statusMessage = 'This live stream doesnt exists';
          res.status(404).end();
          return;
        }
        streamFilters = JSON.parse(collection.filters);
      }
      // If no marking part of filtering are accessible for the user, return
      // Its better to prevent connection instead of having no events accessible
      if (streamFilters.markedBy) {
        const userMarkings = (req.session.user.allowed_marking || []).map((m) => m.internal_id);
        const filterMarkings = (streamFilters.markedBy || []).map((m) => m.id);
        const isUserHaveAccess = filterMarkings.some((m) => userMarkings.includes(m));
        if (!isUserHaveAccess) {
          res.statusMessage = 'You need to have access to specific markings for this live stream';
          res.status(401).end();
          return;
        }
      }
      // Create channel.
      const { channel, client } = createSseChannel(req, res);
      const startListening = utcDate();
      // If stream is starting after, we need to use the main database to catchup
      const reorderedCache = new Set();
      // If empty start date, stream all results corresponding to the filters
      // We need to fetch from this start date until the stream existence
      const catchStartDate = utcDate(isNotEmptyField(startFrom) ? startFrom : FROM_START_STR);
      const after = catchStartDate.toISOString();
      let lastElementUpdate;
      // noinspection UnnecessaryLocalVariableJS
      const queryCallback = async (elements) => {
        for (let index = 0; index < elements.length; index += 1) {
          const { internal_id: elemId } = elements[index];
          const instance = await stixLoadById(req.session.user, elemId);
          const stixData = buildStixData(instance, { clearEmptyValues: true });
          // if (!reorderedCache.has(stixData.id)) {
          const eventId = utcDate(stixData.updated_at).toDate().getTime();
          // Looking for elements published after
          const refs = stixRefsExtractor(stixData, generateStandardId);
          // eslint-disable-next-line prettier/prettier
          const missingElements = await resolveMissingReferences(req, streamFilters, after, stixData.updated_at, refs, reorderedCache);
          if (channel.connected()) {
            let eventIndex = 0;
            // publish missing
            for (let missingIndex = 0; missingIndex < missingElements.length; missingIndex += 1) {
              const missingRef = missingElements[missingIndex];
              if (!reorderedCache.has(missingRef)) {
                const missingInstance = await stixLoadById(req.session.user, missingRef);
                const missingData = buildStixData(missingInstance, { clearEmptyValues: true });
                const markings = missingData.object_marking_refs || [];
                const message = generateCreateMessage(missingInstance);
                const content = { data: missingData, markings, message, version };
                channel.sendEvent(`${eventId}-${eventIndex}`, EVENT_TYPE_CREATE, content);
                eventIndex += 1;
                await wait(channel.delay);
                reorderedCache.add(missingData.id);
              }
            }
            // publish element
            if (!reorderedCache.has(stixData.id)) {
              const markings = stixData.object_marking_refs || [];
              const message = generateCreateMessage(instance);
              channel.sendEvent(`${eventId}-${eventIndex}`, EVENT_TYPE_CREATE, {
                data: stixData,
                markings,
                message,
                version,
              });
              await wait(channel.delay);
            }
            lastElementUpdate = stixData.updated_at;
          } else {
            return channel.connected();
          }
        }
        // Clear the cache as soon as we reach the starting date
        if (utcDate(lastElementUpdate).isAfter(startListening)) {
          reorderedCache.clear();
        }
        await wait(500);
        return channel.connected();
      };
      const queryOptions = convertFiltersToQueryOptions(streamFilters, { after });
      queryOptions.infinite = true;
      queryOptions.callback = queryCallback;
      // If listen delete
      let processor;
      if (listenDelete) {
        processor = createStreamProcessor(req.session.user, req.session.user.user_email, async (elements) => {
          // We need to keep deletion events and patch remove for meta relationships
          const stixDeletions = elements
            .filter((e) => e.topic === EVENT_TYPE_DELETE)
            .filter((d) => {
              // Deletion must be published if UPDATED_AT of delete element < fetching UPDATED_AT
              const deleteUpdatedAt = utcDate(d.data.data.updated_at);
              return deleteUpdatedAt.isSameOrBefore(utcDate(lastElementUpdate));
            });
          for (let deleteIndex = 0; deleteIndex < stixDeletions.length; deleteIndex += 1) {
            const { id: eventId, topic, data } = stixDeletions[deleteIndex];
            client.sendEvent(eventId, topic, data);
          }
        });
        // noinspection ES6MissingAwait
        processor.start();
      }
      await initBroadcasting(req, res, client, processor);
      // Start fetching
      await elList(req.session.user, queryIndices, queryOptions);
      reorderedCache.clear();
    } catch (e) {
      res.statusMessage = `Error in stream: ${e.message}`;
      res.status(500).end();
    }
  };
  return {
    shutdown: () => {
      clearInterval(heartbeat);
      Object.values(broadcastClients).forEach((c) => c.close());
    },
    applyMiddleware: ({ app }) => {
      app.use(`${basePath}/stream`, authenticate);
      app.get(`${basePath}/stream`, genericStreamHandler);
      app.get(`${basePath}/stream/:id`, filteredStreamHandler);
      app.post(`${basePath}/stream/connection/:id`, manageStreamConnectionHandler);
    },
  };
};

export default createSeeMiddleware;
