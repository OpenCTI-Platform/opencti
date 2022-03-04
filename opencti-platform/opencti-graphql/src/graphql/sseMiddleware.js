import * as R from 'ramda';
import { Promise } from 'bluebird';
import LRU from 'lru-cache';
import conf, { basePath, booleanConf, logApp } from '../config/conf';
import { authenticateUserFromRequest, batchGroups, STREAMAPI } from '../domain/user';
import { createStreamProcessor } from '../database/redis';
import { generateInternalId, generateStandardId } from '../schema/identifier';
import { findById, streamCollectionGroups } from '../domain/stream';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE } from '../database/rabbitmq';
import { loadStixById, loadByIdWithMetaRels } from '../database/middleware';
import { convertFiltersToQueryOptions } from '../domain/taxii';
import { elList, ES_MAX_CONCURRENCY, MAX_SPLIT } from '../database/engine';
import {
  generateCreateMessage,
  isNotEmptyField,
  READ_INDEX_INFERRED_ENTITIES,
  READ_INDEX_INFERRED_RELATIONSHIPS,
  READ_INDEX_STIX_META_OBJECTS,
  READ_STIX_INDICES,
} from '../database/utils';
import { convertInstanceToStix } from '../database/stix';
import { BYPASS, isBypassUser } from '../utils/access';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { FROM_START_STR, utcDate } from '../utils/format';
import { stixRefsExtractor } from '../schema/stixEmbeddedRelationship';
import { BASE_TYPE_RELATION } from '../schema/general';

export const MIN_LIVE_STREAM_EVENT_VERSION = 2;

let heartbeat;
const broadcastClients = {};

const DEFAULT_LIVE_STREAM = 'live';
const STREAM_EVENT_VERSION = 3;
const KEEP_ALIVE_INTERVAL_MS = 20000;
const ONE_HOUR = 1000 * 60 * 60;
const MAX_CACHE_TIME = (conf.get('app:live_stream:cache_max_time') ?? 1) * ONE_HOUR;
const MAX_CACHE_SIZE = conf.get('app:live_stream:cache_max_size') ?? 5000;
const INCLUDE_INFERENCES = booleanConf('redis:include_inferences', false);

const isEventGranted = (event, user) => {
  const { data } = event;
  // Granted if:
  // - Event concern directly a marking definition
  // - Event has no specified markings
  // - User have all event markings
  // - User have the bypass capabilities
  const clientMarkings = R.flatten(R.map((m) => [m.standard_id, m.internal_id], user.allowed_marking));
  const isMarkingObject = data.type === ENTITY_TYPE_MARKING_DEFINITION.toLowerCase();
  const isUserHaveAccess = (event.markings || []).length === 0 || event.markings.every((m) => clientMarkings.includes(m));
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
    const auth = await authenticateUserFromRequest(req, res);
    if (auth) {
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
  createHeartbeatProcessor();
  const wait = (ms) => {
    return new Promise((resolve) => setTimeout(() => resolve(), ms));
  };
  const isUserGlobalCapabilityGranted = (user) => {
    const capabilityControl = (s) => s.name === BYPASS || s.name === STREAMAPI;
    return R.find(capabilityControl, user.capabilities || []) !== undefined;
  };
  const resolveMissingReferences = async (queryIndices, req, streamFilters, start, after, missingRefs, cache) => {
    const refsToResolve = missingRefs.filter((m) => !cache.has(m));
    const missingElements = [];
    if (refsToResolve.length > 0) {
      // Resolve missing element standard ids
      const missingIds = [];
      const groupsOfRefsToResolve = R.splitEvery(MAX_SPLIT, refsToResolve);
      const missingRefsResolver = async (refs) => {
        const idsOpts = { ids: refs, connectionFormat: false };
        const findMissing = await elList(req.session.user, queryIndices, idsOpts);
        missingIds.push(...R.uniq(findMissing.map((f) => f.standard_id)));
      };
      await Promise.map(groupsOfRefsToResolve, missingRefsResolver, { concurrency: ES_MAX_CONCURRENCY });
      missingElements.push(...missingIds);
      // Resolve every missing element
      const uniqueIds = R.uniq(missingIds);
      const elementResolver = (id) => loadStixById(req.session.user, id, { withFiles: true });
      const resolvedElements = await Promise.map(uniqueIds, elementResolver, { concurrency: ES_MAX_CONCURRENCY });
      const parentRefs = resolvedElements.map((r) => stixRefsExtractor(r, generateStandardId)).flat();
      if (parentRefs.length > 0) {
        const newMissing = await resolveMissingReferences(queryIndices, req, streamFilters, start, after, parentRefs, cache);
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
      if (!isUserGlobalCapabilityGranted(req.session.user)) {
        res.statusMessage = 'You are not authorized, please check your credentials';
        res.status(401).end();
        return;
      }
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
  const isFullVisibleElement = (instance) => {
    const isMissingRelation = instance.base_type === BASE_TYPE_RELATION;
    const isFullVisibleRelation = isMissingRelation && instance.from && instance.to;
    return isFullVisibleRelation || !isMissingRelation;
  };
  const liveStreamHandler = async (req, res) => {
    const { id } = req.params;
    const queryIndices = [...READ_STIX_INDICES, READ_INDEX_STIX_META_OBJECTS];
    try {
      const version = STREAM_EVENT_VERSION;
      const startFrom = req.query.from || req.headers.from || req.headers['last-event-id'];
      const noDelete = (req.query['listen-delete'] || req.headers['listen-delete']) === 'false';
      const noDependencies = (req.query['no-dependencies'] || req.headers['no-dependencies']) === 'true';
      const withInferences = (req.query['with-inferences'] || req.headers['with-inferences']) === 'true';
      if (withInferences) {
        // Check if platform option is enable
        if (!INCLUDE_INFERENCES) {
          res.statusMessage = 'This live stream requires activated redis include_inferences option';
          res.status(400).end();
          return;
        }
        queryIndices.push(READ_INDEX_INFERRED_ENTITIES, READ_INDEX_INFERRED_RELATIONSHIPS);
      }
      // Build filters
      let streamFilters = {};
      if (id !== DEFAULT_LIVE_STREAM) {
        const collection = await findById(req.session.user, id);
        if (!collection) {
          res.statusMessage = 'This live stream doesnt exists';
          res.status(404).end();
          return;
        }
        const userGroups = await batchGroups(req.session.user, req.session.user.id, {
          batched: false,
          paginate: false,
        });
        const collectionGroups = await streamCollectionGroups(req.session.user, collection);
        if (collectionGroups.length > 0) {
          // User must have one of the collection groups
          const collectionGroupIds = collectionGroups.map((g) => g.id);
          const userGroupIds = userGroups.map((g) => g.id);
          if (!collectionGroupIds.some((c) => userGroupIds.includes(c))) {
            res.statusMessage = 'You need to have access granted for this live stream';
            res.status(401).end();
            return;
          }
        }
        streamFilters = JSON.parse(collection.filters);
      }
      // Check rights
      if (!isUserGlobalCapabilityGranted(req.session.user)) {
        // Access to the global live stream
        res.statusMessage = 'You are not authorized, please check your credentials';
        res.status(401).end();
        return;
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
      // If stream is starting after, we need to use the main database to catchup
      const cache = new LRU({ max: MAX_CACHE_SIZE, ttl: MAX_CACHE_TIME });
      // If empty start date, stream all results corresponding to the filters
      // We need to fetch from this start date until the stream existence
      let after = isNotEmptyField(startFrom) ? startFrom : FROM_START_STR;
      // Also handle event id with redis format stamp or stamp-index
      if (isNotEmptyField(startFrom) && typeof startFrom === 'string') {
        if (!startFrom.includes('-')) {
          after = utcDate(parseInt(startFrom, 10)).toISOString();
        } else if (startFrom.split('-').length === 2) {
          const [timestamp] = startFrom.split('-');
          after = utcDate(parseInt(timestamp, 10)).toISOString();
        }
      }
      let lastElementUpdate;
      // noinspection UnnecessaryLocalVariableJS
      const queryCallback = async (elements) => {
        for (let index = 0; index < elements.length; index += 1) {
          const { internal_id: elemId } = elements[index];
          const instance = await loadByIdWithMetaRels(req.session.user, elemId, { withFiles: true });
          if (isFullVisibleElement(instance)) {
            const stixData = convertInstanceToStix(instance);
            const start = stixData.updated_at;
            const eventId = utcDate(start).toDate().getTime();
            if (channel.connected()) {
              let eventIndex = 0;
              // publish missing if needed
              if (noDependencies === false) {
                const refs = stixRefsExtractor(stixData, generateStandardId);
                const missingElements = await resolveMissingReferences(queryIndices, req, streamFilters, after, start, refs, cache);
                for (let missingIndex = 0; missingIndex < missingElements.length; missingIndex += 1) {
                  const missingRef = missingElements[missingIndex];
                  if (!cache.has(missingRef)) {
                    const missingInstance = await loadByIdWithMetaRels(req.session.user, missingRef);
                    if (isFullVisibleElement(missingInstance)) {
                      const missingData = convertInstanceToStix(missingInstance);
                      const markings = missingData.object_marking_refs || [];
                      const message = generateCreateMessage(missingInstance);
                      const content = { data: missingData, markings, message, version };
                      channel.sendEvent(`${eventId}-${eventIndex}`, EVENT_TYPE_CREATE, content);
                      eventIndex += 1;
                      await wait(channel.delay);
                      cache.set(missingData.id);
                      cache.set(`${missingData.id}-${missingData.updated_at}`);
                    }
                  }
                }
              }
              // publish element
              if (!cache.has(`${stixData.id}-${stixData.updated_at}`)) {
                const markings = stixData.object_marking_refs || [];
                const message = generateCreateMessage(instance);
                channel.sendEvent(`${eventId}-${eventIndex}`, EVENT_TYPE_CREATE, {
                  data: stixData,
                  markings,
                  message,
                  version,
                });
                await wait(channel.delay);
                cache.set(stixData.id);
                cache.set(`${stixData.id}-${stixData.updated_at}`);
              }
              lastElementUpdate = start;
            } else {
              return channel.connected();
            }
          }
        }
        await wait(500);
        return channel.connected();
      };
      const queryOptions = convertFiltersToQueryOptions(streamFilters, { after });
      queryOptions.infinite = true;
      queryOptions.callback = queryCallback;
      // If listen delete
      const userEmail = req.session.user.user_email;
      const processor = createStreamProcessor(req.session.user, userEmail, async (elements) => {
        // We need to keep deletion events
        if (!noDelete) {
          const stixDeletions = elements
            .filter((e) => e.topic === EVENT_TYPE_DELETE)
            .filter((e) => (INCLUDE_INFERENCES ? true : (e.data.data.x_opencti_inference ?? false) === false))
            .filter((d) => {
              // Deletion must be published if UPDATED_AT of delete element < fetching UPDATED_AT
              const deleteUpdatedAt = utcDate(d.data.data.updated_at);
              return deleteUpdatedAt.isSameOrBefore(utcDate(lastElementUpdate));
            });
          for (let deleteIndex = 0; deleteIndex < stixDeletions.length; deleteIndex += 1) {
            const { id: eventId, topic, data } = stixDeletions[deleteIndex];
            client.sendEvent(eventId, topic, data);
          }
        }
        // All event must invalidate the cache
        elements.forEach((e) => cache.delete(e.data.data.id));
      });
      // noinspection ES6MissingAwait
      processor.start();
      await initBroadcasting(req, res, client, processor);
      // Start fetching
      await elList(req.session.user, queryIndices, queryOptions);
    } catch (e) {
      logApp.error(`Error executing live stream ${id}`, { error: e });
      res.statusMessage = `Error in stream ${id}: ${e.message}`;
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
      app.get(`${basePath}/stream/:id`, liveStreamHandler);
      app.post(`${basePath}/stream/connection/:id`, manageStreamConnectionHandler);
    },
  };
};

export default createSeeMiddleware;
