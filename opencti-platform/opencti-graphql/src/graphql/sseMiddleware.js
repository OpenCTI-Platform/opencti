import * as jsonpatch from 'fast-json-patch';
import { Promise } from 'bluebird';
import { LRUCache } from 'lru-cache';
import { now } from 'moment';
import conf, { basePath, logApp } from '../config/conf';
import { TAXIIAPI } from '../domain/user';
import { createStreamProcessor, EVENT_CURRENT_VERSION } from '../database/redis';
import { generateInternalId } from '../schema/identifier';
import { stixLoadById, storeLoadByIdsWithRefs } from '../database/middleware';
import { elCount, elList } from '../database/engine';
import {
  EVENT_TYPE_CREATE,
  EVENT_TYPE_DELETE,
  EVENT_TYPE_DEPENDENCIES,
  EVENT_TYPE_INIT,
  EVENT_TYPE_UPDATE,
  extractIdsFromStoreObject,
  isEmptyField,
  isNotEmptyField,
  READ_INDEX_INFERRED_ENTITIES,
  READ_INDEX_INFERRED_RELATIONSHIPS,
  READ_INDEX_STIX_CORE_RELATIONSHIPS,
  READ_INDEX_STIX_META_OBJECTS,
  READ_INDEX_STIX_SIGHTING_RELATIONSHIPS,
  READ_STIX_INDICES,
} from '../database/utils';
import { BYPASS, computeUserMemberAccessIds, isUserCanAccessStixElement, isUserHasCapability, KNOWLEDGE_ORGANIZATION_RESTRICT, SYSTEM_USER } from '../utils/access';
import { FROM_START_STR, streamEventId, utcDate } from '../utils/format';
import { stixRefsExtractor } from '../schema/stixEmbeddedRelationship';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_OBJECT, buildRefRelationKey, ENTITY_TYPE_CONTAINER, STIX_TYPE_RELATION, STIX_TYPE_SIGHTING } from '../schema/general';
import { UnsupportedError } from '../config/errors';
import { MARKING_FILTER } from '../utils/filtering/filtering-constants';
import { findFiltersFromKey } from '../utils/filtering/filtering-utils';
import { convertFiltersToQueryOptions } from '../utils/filtering/filtering-resolution';
import { getParentTypes } from '../schema/schemaUtils';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { fullRelationsList } from '../database/middleware-loader';
import { RELATION_OBJECT } from '../schema/stixRefRelationship';
import { getEntitiesListFromCache } from '../database/cache';
import { ENTITY_TYPE_STREAM_COLLECTION } from '../schema/internalObject';
import { isStixDomainObjectContainer } from '../schema/stixDomainObject';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
import { generateCreateMessage } from '../database/generate-message';
import { asyncMap, uniqAsyncMap } from '../utils/data-processing';
import { isStixMatchFilterGroup } from '../utils/filtering/filtering-stix/stix-filtering';
import { STIX_CORE_RELATIONSHIPS } from '../schema/stixCoreRelationship';
import { createAuthenticatedContext } from '../http/httpAuthenticatedContext';

import { convertStoreToStix_2_1 } from '../database/stix-2-1-converter';

const broadcastClients = {};
const queryIndices = [...READ_STIX_INDICES, READ_INDEX_STIX_META_OBJECTS];
const DEFAULT_LIVE_STREAM = 'live';
const ONE_HOUR = 1000 * 60 * 60;
const MAX_CACHE_TIME = (conf.get('app:live_stream:cache_max_time') ?? 1) * ONE_HOUR;
const MAX_CACHE_SIZE = conf.get('app:live_stream:cache_max_size') ?? 5000;
const HEARTBEAT_PERIOD = conf.get('app:live_stream:heartbeat_period') ?? 5000;

const sendErrorStatus = (_req, res, httpStatus) => {
  try {
    res.status(httpStatus).end();
  } catch (error) {
    // We don't care but can be interesting for debug.
    logApp.info('Error when trying to kill a session', { error });
  }
};

const createBroadcastClient = (channel) => {
  return {
    id: channel.id,
    userId: channel.userId,
    expirationTime: channel.expirationTime,
    setChannelDelay: (d) => channel.setDelay(d),
    setLastEventId: (id) => channel.setLastEventId(id),
    close: () => channel.close(),
    sendEvent: (eventId, topic, event) => {
      channel.sendEvent(eventId, topic, event);
    },
    sendConnected: (streamInfo) => {
      channel.sendEvent(undefined, 'connected', streamInfo);
    },
  };
};

const authenticate = async (req, res, next) => {
  try {
    const context = await createAuthenticatedContext(req, res, 'stream');
    if (context.user) {
      req.context = context;
      req.userId = context.user.id;
      req.user = context.user;
      req.capabilities = context.user.capabilities;
      req.allowed_marking = context.user.allowed_marking;
      req.expirationTime = utcDate().add(1, 'days').toDate();
      next();
    } else {
      res.statusMessage = 'You are not authenticated, please check your credentials';
      sendErrorStatus(req, res, 401);
    }
  } catch (err) {
    res.statusMessage = `Error in stream: ${err.message}`;
    sendErrorStatus(req, res, 500);
  }
};

const computeUserAndCollection = async (req, res, { context, user, id }) => {
  // Global live stream only available for bypass
  if (id === DEFAULT_LIVE_STREAM) {
    if (!isUserHasCapability(user, BYPASS)) {
      res.statusMessage = 'You are not authorized, please check your credentials';
      sendErrorStatus(req, res, 401);
      return { error: res.statusMessage };
    }
    return { streamFilters: null, collection: null };
  }
  const collections = await getEntitiesListFromCache(context, user, ENTITY_TYPE_STREAM_COLLECTION);
  const collection = collections.find((c) => c.id === id);
  // If collection not found
  if (!collection) {
    res.statusMessage = 'You are not authorized, please check your credentials';
    sendErrorStatus(req, res, 401);
    return { error: res.statusMessage };
  }
  // Check if collection exist and started
  if (!collection.stream_live) {
    res.statusMessage = 'This live stream is stopped';
    sendErrorStatus(req, res, 410);
    logApp.info('This live stream is stopped but still requested', { streamCollectionId: id });
    return { error: 'This live stream is stopped' };
  }
  const streamFilters = JSON.parse(collection.filters);
  // If bypass or public stream
  if (collection.stream_public) {
    return { streamFilters, collection };
  }
  // Access is restricted, user must be authenticated
  if (!user || !isUserHasCapability(user, TAXIIAPI)) {
    res.statusMessage = 'You are not authorized, please check your credentials';
    sendErrorStatus(req, res, 401);
    return { error: res.statusMessage };
  }
  // Access is restricted, check the current user
  const userAccessIds = computeUserMemberAccessIds(user);
  const collectionAccessIds = (collection.restricted_members ?? []).map((a) => a.id);
  if (collectionAccessIds.length > 0) { // If restrictions have been setup
    if (!isUserHasCapability(user, BYPASS) && !collectionAccessIds.some((accessId) => userAccessIds.includes(accessId))) {
      res.statusMessage = 'You are not authorized, please check your credentials';
      sendErrorStatus(req, res, 401);
      return { error: res.statusMessage };
    }
  }
  // If no marking part of filtering are accessible for the user, return
  // It's better to prevent connection instead of having no events accessible
  const objectMarkingFilters = findFiltersFromKey(streamFilters.filters, MARKING_FILTER, 'eq');
  if (objectMarkingFilters.length > 0) {
    const objectMarkingFilter = objectMarkingFilters[0];
    const userMarkings = (user.allowed_marking || []).map((m) => m.internal_id);
    const filterMarkings = objectMarkingFilter.values;
    const isUserHaveAccess = filterMarkings.some((m) => userMarkings.includes(m));
    if (!isUserHaveAccess) {
      res.statusMessage = 'You need to have access to specific markings for this live stream';
      sendErrorStatus(req, res, 401);
      return { error: res.statusMessage };
    }
  }
  return { streamFilters, collection };
};

const authenticateForPublic = async (req, res, next) => {
  const context = await createAuthenticatedContext(req, res, 'stream_authenticate');
  const user = context.user ?? SYSTEM_USER;
  req.context = context;
  req.userId = user.id;
  req.user = user;
  req.capabilities = user.capabilities;
  req.allowed_marking = user.allowed_marking;
  req.expirationTime = utcDate().add(1, 'days').toDate();
  const { error, collection, streamFilters } = await computeUserAndCollection(req, res, {
    context,
    user: req.user,
    id: req.params.id
  });
  if (error || (!collection?.stream_public && !context.user)) {
    res.statusMessage = 'You are not authenticated, please check your credentials';
    sendErrorStatus(req, res, 401);
  } else {
    req.collection = collection;
    req.streamFilters = streamFilters;
    next();
  }
};

const createSseMiddleware = () => {
  const wait = (ms) => {
    return new Promise((resolve) => setTimeout(() => resolve(), ms));
  };
  const extractQueryParameter = (req, param) => {
    const paramData = req.query[param];
    if (paramData && Array.isArray(paramData) && paramData.length > 0) {
      return paramData.at(0);
    }
    return paramData;
  };

  const resolveMissingReferences = async (context, user, missingRefs, cache) => {
    const refsToResolve = missingRefs.filter((m) => !cache.has(m));
    if (refsToResolve.length === 0) {
      return [];
    }

    const missingElements = await storeLoadByIdsWithRefs(context, user, refsToResolve);
    if (missingElements.length === 0) {
      return [];
    }

    const allRefs = await uniqAsyncMap(missingElements, (r) => stixRefsExtractor(convertStoreToStix_2_1(r)), undefined, { flat: true });
    if (allRefs.length === 0) {
      return missingElements;
    }

    const resolvedMissingIds = new Set(await asyncMap(missingElements, (elem) => extractIdsFromStoreObject(elem), undefined, { flat: true }));
    const parentRefs = allRefs.filter((parentId) => !resolvedMissingIds.has(parentId));
    if (parentRefs.length === 0) {
      return missingElements;
    }

    const newMissing = await resolveMissingReferences(context, user, parentRefs, cache);
    if (newMissing.length === 0) {
      return missingElements;
    }

    return newMissing.concat(missingElements);
  };

  const initBroadcasting = async (req, res, client, processor) => {
    const broadcasterInfo = processor ? await processor.info() : {};
    req.on('close', () => {
      client.close();
      delete broadcastClients[client.id];
      logApp.info(`[STREAM] Closing stream processor for ${client.id}`);
      processor.shutdown();
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
  const createSseChannel = (req, res, startId) => {
    let lastEventId = startId;
    const channel = {
      id: generateInternalId(),
      delay: parseInt(extractQueryParameter(req, 'delay') || req.headers['event-delay'] || 0, 10),
      user: req.user,
      userId: req.userId,
      expirationTime: req.expirationTime,
      allowed_marking: req.allowed_marking,
      capabilities: req.capabilities,
      setDelay: (d) => {
        channel.delay = d;
      },
      setLastEventId: (id) => { lastEventId = id; },
      connected: () => !res.finished,
      sendEvent: (eventId, topic, event) => {
        // Write on an already terminated response
        if (res.finished || !res.writable) {
          return;
        }
        let message = '';
        if (eventId) {
          lastEventId = eventId;
          message += `id: ${eventId}\n`;
        }
        if (topic) {
          message += `event: ${topic}\n`;
        }
        if (event) {
          message += 'data: ';
          const isDataTopic = eventId && topic !== 'heartbeat';
          if (isDataTopic && req.user && !isUserHasCapability(req.user, KNOWLEDGE_ORGANIZATION_RESTRICT)) {
            const filtered = { ...event };
            delete filtered.data.extensions[STIX_EXT_OCTI].granted_refs;
            message += JSON.stringify(filtered);
          } else {
            message += JSON.stringify(event);
          }
          message += '\n';
        }
        message += '\n';
        res.write(message);
        res.flush();
      },
      close: () => {
        logApp.info('[STREAM] Closing SSE channel', { clientId: channel.userId });
        if (heartbeatInterval) clearInterval(heartbeatInterval);
        channel.expirationTime = 0;
        if (!res.finished) {
          try {
            res.end();
          } catch (e) {
            logApp.error('Stream session destroy fail', { cause: e, action: 'close', clientId: channel.userId });
          }
        }
      },
    };
    const heartTimer = () => {
      if (lastEventId) {
        const [idTime] = lastEventId.split('-');
        const idDate = utcDate(parseInt(idTime, 10)).toISOString();
        channel.sendEvent(lastEventId, 'heartbeat', idDate);
      }
    };
    const heartbeatInterval = setInterval(heartTimer, HEARTBEAT_PERIOD);
    return { channel, client: createBroadcastClient(channel) };
  };
  const genericStreamHandler = async (req, res) => {
    try {
      const { user, context } = req;
      const paramStartFrom = extractQueryParameter(req, 'from') || req.headers.from || req.headers['last-event-id'];
      const startStreamId = convertParameterToStreamId(paramStartFrom);
      // Generic stream only available for bypass users
      if (!isUserHasCapability(user, BYPASS)) {
        res.statusMessage = 'Consume generic stream is only authorized for bypass user';
        sendErrorStatus(req, res, 401);
        return;
      }
      const { client } = createSseChannel(req, res, startStreamId);
      const opts = { autoReconnect: true };
      const processor = createStreamProcessor(user, user.user_email, async (elements, lastEventId) => {
        // Process the event messages
        for (let index = 0; index < elements.length; index += 1) {
          const { id: eventId, event, data } = elements[index];
          const instanceAccessible = await isUserCanAccessStixElement(context, user, data.data);
          if (instanceAccessible) {
            client.sendEvent(eventId, event, data);
          }
        }
        client.setLastEventId(lastEventId);
      }, opts);
      await initBroadcasting(req, res, client, processor);
      await processor.start(startStreamId);
    } catch (err) {
      res.statusMessage = `Error in stream: ${err.message}`;
      sendErrorStatus(req, res, 500);
    }
  };
  const manageStreamConnectionHandler = async (req, res) => {
    try {
      const { id } = req.params;
      const client = broadcastClients[id];
      if (client) {
        if (client.userId !== req.userId) {
          res.statusMessage = 'You cant access this resource';
          sendErrorStatus(req, res, 401);
        } else {
          const { delay = 0 } = req.body;
          client.setChannelDelay(delay);
          res.json({ message: 'ok' });
        }
      } else {
        res.statusMessage = 'This is not your connection';
        sendErrorStatus(req, res, 401);
      }
    } catch (err) {
      res.statusMessage = `Error in connection management: ${err.message}`;
      sendErrorStatus(req, res, 500);
    }
  };
  const resolveAndPublishMissingRefs = async (context, cache, channel, req, eventId, stixData) => {
    const refs = stixRefsExtractor(stixData);
    const missingInstances = await resolveMissingReferences(context, req.user, refs, cache);
    // const missingInstances = await storeLoadByIdsWithRefs(context, req.user, missingElements);
    if (stixData.type === STIX_TYPE_RELATION || stixData.type === STIX_TYPE_SIGHTING) {
      const missingAllPerIds = missingInstances.map((m) => [m.internal_id, m.standard_id, ...(m.x_opencti_stix_ids ?? [])].map((id) => ({ id, value: m }))).flat();
      const missingMap = new Map(missingAllPerIds.map((m) => [m.id, m.value]));
      // Check for a relation that the from and the to is correctly accessible.
      const fromId = stixData.source_ref ?? stixData.sighting_of_ref;
      const toId = stixData.target_ref ?? stixData.where_sighted_refs[0];
      const hasFrom = missingMap.has(fromId) || cache.has(fromId);
      const hasTo = missingMap.has(toId) || cache.has(toId);
      if (!hasFrom || !hasTo) {
        return false;
      }
    }
    for (let missingIndex = 0; missingIndex < missingInstances.length; missingIndex += 1) {
      const missingInstance = missingInstances[missingIndex];
      if (!cache.has(missingInstance.standard_id) && channel.connected()) {
        const missingData = convertStoreToStix_2_1(missingInstance);
        const message = generateCreateMessage(missingInstance);
        const origin = { referer: EVENT_TYPE_DEPENDENCIES };
        const content = { data: missingData, message, origin, version: EVENT_CURRENT_VERSION };
        channel.sendEvent(eventId, EVENT_TYPE_CREATE, content);
        cache.set(missingData.id, 'hit');
        await wait(channel.delay);
      }
    }
    return true;
  };
  const resolveAndPublishDependencies = async (context, noDependencies, cache, channel, req, eventId, stix) => {
    // Resolving REFS
    const isValidResolution = await resolveAndPublishMissingRefs(context, cache, channel, req, eventId, stix);
    // Resolving CORE RELATIONS
    if (isValidResolution && noDependencies === false) {
      const allRelCallback = async (relations) => {
        const notCachedRelations = relations.filter((m) => !cache.has(m.standard_id));
        const findRelIds = notCachedRelations.map((r) => r.internal_id);
        const missingRelations = await storeLoadByIdsWithRefs(context, req.user, findRelIds);
        for (let relIndex = 0; relIndex < missingRelations.length; relIndex += 1) {
          const missingRelation = missingRelations[relIndex];
          if (channel.connected()) {
            const stixRelation = convertStoreToStix_2_1(missingRelation);
            // Resolve refs
            await resolveAndPublishMissingRefs(context, cache, channel, req, eventId, stixRelation);
            // Publish relations
            const message = generateCreateMessage(missingRelation);
            const origin = { referer: EVENT_TYPE_DEPENDENCIES };
            const content = { data: stixRelation, message, origin, version: EVENT_CURRENT_VERSION };
            channel.sendEvent(eventId, EVENT_TYPE_CREATE, content);
            cache.set(stixRelation.id, 'hit');
          }
        }
        // Send the Heartbeat with last event id
        await wait(channel.delay);
        // Return channel status to stop the iteration if channel is disconnected
        return channel.connected();
      };
      const allRelOptions = {
        fromOrToId: stix.extensions[STIX_EXT_OCTI].id,
        indices: [READ_INDEX_STIX_CORE_RELATIONSHIPS, READ_INDEX_STIX_SIGHTING_RELATIONSHIPS],
        callback: allRelCallback
      };
      const relationTypes = [ABSTRACT_STIX_CORE_RELATIONSHIP, STIX_SIGHTING_RELATIONSHIP];
      await fullRelationsList(context, req.user, relationTypes, allRelOptions);
    }
    return isValidResolution;
  };
  const isFiltersEntityTypeMatch = (filters, type) => {
    let match = false;
    const matches = [];
    const fromAllTypes = [type, ...getParentTypes(type)];
    const entityTypeFilters = findFiltersFromKey(filters.filters, 'entity_type', 'eq');
    const entityTypeFilter = entityTypeFilters.length > 0 ? entityTypeFilters[0] : undefined;
    const entityTypeFilterValues = entityTypeFilter?.values ?? [];
    // eslint-disable-next-line no-restricted-syntax
    for (const id of entityTypeFilterValues) {
      // consider the operator
      if (entityTypeFilter.operator === 'not_eq') {
        if (!fromAllTypes.includes(id)) {
          matches.push(true);
        } else {
          matches.push(false);
        }
      } else if (fromAllTypes.includes(id)) { // operator = 'eq'
        matches.push(true);
      } else {
        matches.push(false);
      }
      // consider the mode
      if (entityTypeFilter.mode === 'and') {
        if (!matches.includes(false)) {
          match = true;
        }
      } else if (matches.includes(true)) { // mode = 'or'
        match = true;
      }
    }
    return match;
  };
  const publishRelationDependencies = async (context, noDependencies, cache, channel, req, streamFilters, element) => {
    const { user } = req;
    const { id: eventId, data: eventData } = element;
    const { type, data: stix, message } = eventData;
    const isRel = stix.type === 'relationship';
    const fromId = isRel ? stix.source_ref : stix.sighting_of_ref;
    const toId = isRel ? stix.target_ref : stix.where_sighted_refs[0];
    // Pre-filter by type to prevent resolutions as much as possible.
    const entityTypeFilters = findFiltersFromKey(streamFilters.filters, 'entity_type', 'eq');
    if (entityTypeFilters.length > 0 && entityTypeFilters[0].values.length > 0) {
      const fromType = isRel ? stix.extensions[STIX_EXT_OCTI].source_type : stix.extensions[STIX_EXT_OCTI].sighting_of_type;
      const matchingFrom = isFiltersEntityTypeMatch(streamFilters, fromType);
      const toType = isRel ? stix.extensions[STIX_EXT_OCTI].target_type : stix.extensions[STIX_EXT_OCTI].where_sighted_types[0];
      const matchingTo = isFiltersEntityTypeMatch(streamFilters, toType);
      if (!matchingFrom && !matchingTo) {
        return;
      }
    }
    const [fromStix, toStix] = await Promise.all([stixLoadById(context, user, fromId), stixLoadById(context, user, toId)]);
    if (fromStix && toStix) {
      // As we resolved at now, data can be deleted now.
      // We are force to resolve because stream cannot contain all dependencies on each event.
      const isFromVisible = await isStixMatchFilterGroup(context, user, fromStix, streamFilters);
      const isToVisible = await isStixMatchFilterGroup(context, user, toStix, streamFilters);
      if (isFromVisible || isToVisible) {
        await resolveAndPublishDependencies(context, noDependencies, cache, channel, req, eventId, stix);
        // From or to are visible, consider it as a dependency
        const origin = { referer: EVENT_TYPE_DEPENDENCIES };
        const content = { data: stix, message, origin, version: EVENT_CURRENT_VERSION };
        channel.sendEvent(eventId, type, content);
      }
    }
  };
  const convertParameterToDate = (param) => {
    if (!param || typeof param !== 'string') {
      return undefined;
    }
    if (param === '0' || param === '0-0') {
      return FROM_START_STR;
    }
    const isFromEventFormat = param.includes('-') && param.split('-').length === 2;
    if (isFromEventFormat) {
      const [timestamp] = param.split('-');
      return utcDate(parseInt(timestamp, 10)).toISOString();
    }
    const streamStartDate = utcDate(param);
    if (streamStartDate.isValid()) {
      return streamStartDate.toISOString();
    }
    return undefined;
  };
  const convertParameterToStreamId = (param) => {
    if (!param || typeof param !== 'string') {
      return undefined;
    }
    if (param === '0' || param === '0-0') {
      return '0-0';
    }
    const isFromEventFormat = param.includes('-') && param.split('-').length === 2;
    if (isFromEventFormat) {
      return param;
    }
    const startFrom = utcDate(param);
    if (startFrom.isValid()) {
      return `${startFrom.valueOf()}-0`;
    }
    return undefined;
  };

  const liveStreamHandler = async (req, res) => {
    const { id } = req.params;
    try {
      const cache = new LRUCache({ max: MAX_CACHE_SIZE, ttl: MAX_CACHE_TIME });
      const { user, context } = req;
      // If stream is starting after, we need to use the main database to catchup
      const paramStartFrom = extractQueryParameter(req, 'from') || req.headers.from || req.headers['last-event-id'];
      const startIsoDate = convertParameterToDate(paramStartFrom);
      const startStreamId = convertParameterToStreamId(paramStartFrom);
      const recoverToParameter = extractQueryParameter(req, 'recover') || req.headers.recover || req.headers['recover-date'];
      const recoverIsoDate = convertParameterToDate(recoverToParameter);
      const recoverStreamId = convertParameterToStreamId(recoverToParameter);
      const noDependencies = (req.query['no-dependencies'] || req.headers['no-dependencies'] || req.query['no-relationships'] || req.headers['no-relationships']) === 'true';
      const publishDependencies = noDependencies === false;
      const noDelete = (req.query['listen-delete'] || req.headers['listen-delete']) === 'false';
      const publishDeletion = noDelete === false;
      const withInferences = (req.query['with-inferences'] || req.headers['with-inferences']) === 'true';
      const streamQueryIndices = [...queryIndices];
      if (withInferences) {
        streamQueryIndices.push(READ_INDEX_INFERRED_ENTITIES, READ_INDEX_INFERRED_RELATIONSHIPS);
      }

      let { streamFilters, collection } = req;

      // Create channel.
      const { channel, client } = createSseChannel(req, res, startStreamId);
      // If empty start date, stream all results corresponding to the filters
      // We need to fetch from this start date until the stream existence
      if (isNotEmptyField(recoverIsoDate) && isEmptyField(startIsoDate)) {
        throw UnsupportedError('Recovery mode is only possible with a start date.');
      }
      // Init stream and broadcasting
      let error;
      const userEmail = user.user_email;
      const opts = { autoReconnect: true };
      const processor = createStreamProcessor(user, userEmail, async (elements, lastEventId) => {
        // Default Live collection doesn't have a stored Object associated
        if (!error && (!collection || collection.stream_live)) {
          // Process the stream elements
          for (let index = 0; index < elements.length; index += 1) {
            const element = elements[index];
            const { id: eventId, event, data: eventData } = element;
            const { type, data: stix, version: eventVersion, context: evenContext, event_id } = eventData;
            const updateTime = stix.extensions[STIX_EXT_OCTI]?.updated_at ?? now();
            eventData.event_id = event_id ?? streamEventId(updateTime, index);
            const isRelation = stix.type === 'relationship' || stix.type === 'sighting';
            // New stream support only v4+ events.
            const isCompatibleVersion = parseInt(eventVersion ?? '0', 10) >= 4;
            if (isCompatibleVersion) {
              // Check for inferences
              const elementInternalId = stix.extensions[STIX_EXT_OCTI].id;
              const isInferredData = stix.extensions[STIX_EXT_OCTI].is_inferred;
              const elementType = stix.extensions[STIX_EXT_OCTI].type;
              if (!isInferredData || (isInferredData && withInferences)) {
                const isCurrentlyVisible = await isStixMatchFilterGroup(context, user, stix, streamFilters);
                if (type === EVENT_TYPE_UPDATE) {
                  const { newDocument: previous } = jsonpatch.applyPatch(structuredClone(stix), evenContext.reverse_patch);
                  const isPreviouslyVisible = await isStixMatchFilterGroup(context, user, previous, streamFilters);
                  if (isPreviouslyVisible && !isCurrentlyVisible && publishDeletion) { // No longer visible
                    client.sendEvent(eventId, EVENT_TYPE_DELETE, eventData);
                    cache.set(stix.id, 'hit');
                  } else if (!isPreviouslyVisible && isCurrentlyVisible) { // Newly visible
                    const isValidResolution = await resolveAndPublishDependencies(context, noDependencies, cache, channel, req, eventId, stix);
                    if (isValidResolution) {
                      client.sendEvent(eventId, EVENT_TYPE_CREATE, eventData);
                      cache.set(stix.id, 'hit');
                    }
                  } else if (isCurrentlyVisible) { // Just an update
                    const isValidResolution = await resolveAndPublishDependencies(context, noDependencies, cache, channel, req, eventId, stix);
                    if (isValidResolution) {
                      client.sendEvent(eventId, event, eventData);
                      cache.set(stix.id, 'hit');
                    }
                  } else if (isRelation && publishDependencies) { // Update but not visible - relation type
                    // In case of relationship publication, from or to can be related to something that
                    // is part of the filtering. We can consider this as dependencies
                    await publishRelationDependencies(context, noDependencies, cache, channel, req, streamFilters, element);
                  } else if (!isStixDomainObjectContainer(elementType)) { // Update but not visible - entity type
                    // If entity is not a container, it can be part of a container that is authorized by the filters
                    // If it's the case, the element must be published
                    // So we need to list the containers with stream filters restricted through type and the connected element rel
                    const queryOptions = await convertFiltersToQueryOptions(streamFilters, {
                      defaultTypes: [ENTITY_TYPE_CONTAINER], // Looking only for containers
                      extraFilters: [{ key: [buildRefRelationKey(RELATION_OBJECT)], values: [elementInternalId] }] // Connected rel
                    });
                    const countRelatedContainers = await elCount(context, user, streamQueryIndices, queryOptions);
                    // At least one container is matching the filter, so publishing the event
                    if (countRelatedContainers > 0) {
                      await resolveAndPublishMissingRefs(context, cache, channel, req, eventId, stix);
                      client.sendEvent(eventId, event, eventData);
                      cache.set(stix.id, 'hit');
                    }
                  }
                } else if (isCurrentlyVisible) {
                  if (type === EVENT_TYPE_DELETE) {
                    if (publishDeletion) {
                      client.sendEvent(eventId, event, eventData);
                      cache.set(stix.id, 'hit');
                    }
                  } else { // Create and merge
                    const isValidResolution = await resolveAndPublishDependencies(context, noDependencies, cache, channel, req, eventId, stix);
                    if (isValidResolution) {
                      client.sendEvent(eventId, event, eventData);
                      cache.set(stix.id, 'hit');
                    }
                  }
                } else if (isRelation && publishDependencies) { // Not an update and not visible
                  // In case of relationship publication, from or to can be related to something that
                  // is part of the filtering. We can consider this as dependencies
                  await publishRelationDependencies(context, noDependencies, cache, channel, req, streamFilters, element);
                }
              }
            }
          }
        }
        // Wait to prevent flooding
        channel.setLastEventId(lastEventId);
        await wait(channel.delay);
        const newComputed = await computeUserAndCollection(req, res, { id, user, context });
        streamFilters = newComputed.streamFilters;
        collection = newComputed.collection;
        error = newComputed.error;
      }, opts);
      await initBroadcasting(req, res, client, processor);
      // After recovery start the stream listening
      const startMessage = startStreamId ? `${startStreamId} / ${startIsoDate}` : 'now';
      const recoveringMessage = recoverIsoDate ? ` - recovering to ${recoverIsoDate}` : '';
      logApp.info(`[STREAM] Listening stream ${id} from ${startMessage}${recoveringMessage}`);
      // Start recovery if needed
      const isRecoveryMode = isNotEmptyField(recoverIsoDate) && utcDate(recoverIsoDate).isAfter(startIsoDate);
      if (isRecoveryMode) {
        // noinspection UnnecessaryLocalVariableJS
        const queryCallback = async (elements) => {
          const workingElementsIds = elements.filter((e) => !cache.has(e.standard_id)).map((e) => e.internal_id);
          const instances = await storeLoadByIdsWithRefs(context, user, workingElementsIds);
          for (let index = 0; index < instances.length; index += 1) {
            const instance = instances[index];
            const stixData = convertStoreToStix_2_1(instance);
            const stixUpdatedAt = stixData.extensions[STIX_EXT_OCTI].updated_at;
            const eventId = streamEventId(stixUpdatedAt);
            if (channel.connected()) {
              // publish missing dependencies if needed
              const isValidResolution = await resolveAndPublishDependencies(context, noDependencies, cache, channel, req, eventId, stixData);
              // publish element
              if (isValidResolution && !cache.has(stixData.id)) {
                const message = generateCreateMessage(instance);
                const origin = { referer: EVENT_TYPE_INIT };
                const eventData = { data: stixData, message, origin, version: EVENT_CURRENT_VERSION };
                channel.sendEvent(eventId, EVENT_TYPE_CREATE, eventData);
                cache.set(stixData.id, 'hit');
              }
            } else {
              return channel.connected();
            }
          }
          await wait(channel.delay);
          return channel.connected();
        };
        const queryOptions = await convertFiltersToQueryOptions(streamFilters, {
          defaultTypes: [STIX_CORE_RELATIONSHIPS, STIX_SIGHTING_RELATIONSHIP, ABSTRACT_STIX_OBJECT],
          after: startIsoDate,
          before: recoverIsoDate
        });
        queryOptions.callback = queryCallback;
        await elList(context, user, streamQueryIndices, queryOptions);
      }
      // noinspection ES6MissingAwait
      processor.start(isRecoveryMode ? recoverStreamId : startStreamId).catch((reason) => {
        logApp.error('Stream error', { cause: reason });
      });
    } catch (e) {
      logApp.error('Stream handling error', { cause: e, id, type: 'live' });
      res.statusMessage = `Error in stream ${id}: ${e.message}`;
      sendErrorStatus(req, res, 500);
    }
  };
  return {
    shutdown: () => {
      Object.values(broadcastClients).forEach((c) => c.close());
    },
    applyMiddleware: ({ app }) => {
      app.get(`${basePath}/stream`, authenticate, genericStreamHandler);
      app.get(`${basePath}/stream/:id`, authenticateForPublic, liveStreamHandler);
      app.post(`${basePath}/stream/connection/:id`, authenticate, manageStreamConnectionHandler);
    },
  };
};
export default createSseMiddleware;
