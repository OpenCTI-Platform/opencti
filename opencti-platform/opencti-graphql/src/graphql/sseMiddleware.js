import * as R from 'ramda';
import * as jsonpatch from 'fast-json-patch';
import { Promise } from 'bluebird';
import LRU from 'lru-cache';
import conf, { basePath, booleanConf, logApp } from '../config/conf';
import { authenticateUserFromRequest, batchGroups, STREAMAPI } from '../domain/user';
import { createStreamProcessor, EVENT_CURRENT_VERSION, STREAM_BATCH_TIME } from '../database/redis';
import { generateInternalId, generateStandardId } from '../schema/identifier';
import { findById, streamCollectionGroups } from '../domain/stream';
import {
  EVENT_TYPE_CREATE,
  EVENT_TYPE_DELETE,
  EVENT_TYPE_DEPENDENCIES,
  EVENT_TYPE_INIT,
  EVENT_TYPE_UPDATE
} from '../database/rabbitmq';
import { internalLoadById, stixLoadById, stixLoadByIds, storeLoadByIdWithRefs } from '../database/middleware';
import { elList, ES_MAX_CONCURRENCY, MAX_SPLIT } from '../database/engine';
import {
  generateCreateMessage,
  isEmptyField,
  isNotEmptyField,
  READ_INDEX_INFERRED_ENTITIES,
  READ_INDEX_INFERRED_RELATIONSHIPS,
  READ_INDEX_STIX_CORE_RELATIONSHIPS,
  READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS,
  READ_INDEX_STIX_META_OBJECTS,
  READ_INDEX_STIX_SIGHTING_RELATIONSHIPS,
  READ_STIX_INDICES,
} from '../database/utils';
import { BYPASS, isBypassUser, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { FROM_START_STR, utcDate } from '../utils/format';
import { stixRefsExtractor } from '../schema/stixEmbeddedRelationship';
import {
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP,
  BASE_TYPE_RELATION
} from '../schema/general';
import { convertStoreToStix } from '../database/stix-converter';
import { UnsupportedError } from '../config/errors';
import { adaptFiltersFrontendFormat, convertFiltersToQueryOptions, TYPE_FILTER } from '../utils/filtering';
import { getParentTypes } from '../schema/schemaUtils';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from '../types/stix-extensions';
import { listAllRelations } from '../database/middleware-loader';

const broadcastClients = {};
const queryIndices = [...READ_STIX_INDICES, READ_INDEX_STIX_META_OBJECTS];
const DEFAULT_LIVE_STREAM = 'live';
const ONE_HOUR = 1000 * 60 * 60;
const MAX_CACHE_TIME = (conf.get('app:live_stream:cache_max_time') ?? 1) * ONE_HOUR;
const MAX_CACHE_SIZE = conf.get('app:live_stream:cache_max_size') ?? 5000;
const INCLUDE_INFERENCES = booleanConf('redis:include_inferences', false);

const MARKING_FILTER = 'markedBy';
const LABEL_FILTER = 'labelledBy';
const CREATOR_FILTER = 'createdBy';
const SCORE_FILTER = 'x_opencti_score';
const DETECTION_FILTER = 'x_opencti_detection';
const CONFIDENCE_FILTER = 'confidence';
const REVOKED_FILTER = 'revoked';
const PATTERN_FILTER = 'pattern_type';

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
  let lastHeartbeat;
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
    sendHeartbeat: (eventId) => {
      // Debounce the heartbeat to STREAM_BATCH_TIME
      const now = new Date().getTime();
      if (lastHeartbeat === undefined || (now - lastHeartbeat) > STREAM_BATCH_TIME) {
        const [idTime] = eventId.split('-');
        const idDate = utcDate(parseInt(idTime, 10)).toISOString();
        channel.sendEvent(eventId, 'heartbeat', idDate);
        lastHeartbeat = now;
      }
    },
    sendConnected: (streamInfo) => {
      channel.sendEvent(undefined, 'connected', streamInfo);
    },
  };
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
  const wait = (ms) => {
    return new Promise((resolve) => setTimeout(() => resolve(), ms));
  };
  const extractQueryParameter = (req, param) => {
    const paramData = req.query[param];
    if (paramData && Array.isArray(paramData)) {
      return R.head(paramData);
    }
    return paramData;
  };
  const isUserGlobalCapabilityGranted = (user) => {
    const capabilityControl = (s) => s.name === BYPASS || s.name === STREAMAPI;
    return R.find(capabilityControl, user.capabilities || []) !== undefined;
  };
  const resolveMissingReferences = async (req, streamFilters, missingRefs, cache) => {
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
      const resolvedElements = await stixLoadByIds(req.session.user, uniqueIds);
      const parentRefs = resolvedElements.map((r) => stixRefsExtractor(r, generateStandardId)).flat();
      if (parentRefs.length > 0) {
        const newMissing = await resolveMissingReferences(req, streamFilters, parentRefs, cache);
        missingElements.unshift(...newMissing);
      }
    }
    return missingElements;
  };
  const initBroadcasting = async (req, res, client, processor) => {
    const broadcasterInfo = processor ? await processor.info() : {};
    req.on('close', () => {
      req.finished = true;
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
  const createSseChannel = (req, res) => {
    const channel = {
      id: generateInternalId(),
      delay: parseInt(extractQueryParameter(req, 'delay') || req.headers['event-delay'] || 10, 10),
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
          // Write on an already terminated response
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
      const processor = createStreamProcessor(req.session.user, req.session.user.user_email, async (elements, lastEventId) => {
        // Process the event messages
        for (let index = 0; index < elements.length; index += 1) {
          const { id: eventId, event, data } = elements[index];
          client.sendEvent(eventId, event, data);
        }
        // Send the Heartbeat with last event id
        client.sendHeartbeat(lastEventId);
      });
      await initBroadcasting(req, res, client, processor);
      let lastEventId = extractQueryParameter(req, 'from') || req.headers['last-event-id'];
      if (lastEventId && lastEventId.includes('T')) {
        const startDate = utcDate(lastEventId);
        lastEventId = startDate.isValid() ? `${startDate.toDate().getTime()}-0` : 'live';
      }
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
    if (isMissingRelation) {
      return instance.from && instance.to;
    }
    return true;
  };
  const filterCacheResolver = async (values, filterCache) => {
    const filterIds = values.map((v) => v.id);
    const filterRefs = [];
    for (let i = 0; i < filterIds.length; i += 1) {
      const filterId = filterIds[i];
      const fromCache = filterCache.get(filterId);
      if (fromCache) {
        filterRefs.push(fromCache.standard_id);
      } else {
        const creator = await internalLoadById(SYSTEM_USER, filterId);
        filterRefs.push(creator.standard_id);
        filterCache.set(filterId, creator);
      }
    }
    return filterRefs;
  };
  const isInstanceMatchFilters = async (instance, filters, filterCache) => {
    // Pre-filter transformation to handle specific frontend format
    const adaptedFilters = adaptFiltersFrontendFormat(filters);
    // User is granted, but we still need to apply filters if needed
    const filterEntries = Object.entries(adaptedFilters);
    for (let index = 0; index < filterEntries.length; index += 1) {
      const [type, { operator, values }] = filterEntries[index];
      // Markings filtering
      if (type === MARKING_FILTER) {
        if (values.length === 0) {
          return true;
        }
        const markings = instance.object_marking_refs || [];
        if (values.length > 0 && markings.length === 0) {
          return false;
        }
        const filterMarkingRefs = await filterCacheResolver(values, filterCache);
        const found = filterMarkingRefs.some((r) => markings.includes(r));
        if (!found) {
          return false;
        }
      }
      // Entity type filtering
      if (type === TYPE_FILTER) {
        const instanceType = instance.extensions[STIX_EXT_OCTI].type;
        const instanceAllTypes = [instanceType, ...getParentTypes(instanceType)];
        let found = false;
        if (values.length === 0) {
          found = true;
        } else {
          // eslint-disable-next-line no-restricted-syntax
          for (const filter of values) {
            if (instanceAllTypes.includes(filter.id)) {
              found = true;
            }
          }
        }
        if (!found) {
          return false;
        }
      }
      // Creator filtering
      if (type === CREATOR_FILTER) {
        if (values.length === 0) {
          return true;
        }
        if (values.length > 0 && instance.created_by_ref === undefined) {
          return false;
        }
        const filterCreationRefs = await filterCacheResolver(values, filterCache);
        const found = filterCreationRefs.includes(instance.created_by_ref);
        if (!found) {
          return false;
        }
      }
      // Labels filtering
      if (type === LABEL_FILTER) {
        const labels = [...(instance.labels ?? []), ...(instance.extensions[STIX_EXT_OCTI_SCO]?.labels ?? [])];
        const found = values.map((v) => v.value).some((r) => labels.includes(r));
        if (!found) {
          return false;
        }
      }
      // Boolean filtering
      if (type === REVOKED_FILTER || type === DETECTION_FILTER) {
        const { id } = R.head(values);
        const found = (id === 'true') === instance.revoked;
        if (!found) {
          return false;
        }
      }
      // Numeric filtering
      if (type === SCORE_FILTER || type === CONFIDENCE_FILTER) {
        const { id } = R.head(values);
        let found = false;
        const numeric = parseInt(id, 10);
        switch (operator) {
          case 'lt':
            found = instance[type] < numeric;
            break;
          case 'lte':
            found = instance[type] <= numeric;
            break;
          case 'gt':
            found = instance[type] > numeric;
            break;
          case 'gte':
            found = instance[type] >= numeric;
            break;
          default:
            found = instance[type] === numeric;
        }
        if (!found) {
          return false;
        }
      }
      // String filtering
      if (type === PATTERN_FILTER) {
        const { id } = R.head(values);
        const found = id === instance[type];
        if (!found) {
          return false;
        }
      }
    }
    return true;
  };
  const resolveAndPublishMissingRefs = async (cache, channel, req, streamFilters, eventId, stixData) => {
    const refs = stixRefsExtractor(stixData, generateStandardId);
    const missingElements = await resolveMissingReferences(req, streamFilters, refs, cache);
    for (let missingIndex = 0; missingIndex < missingElements.length; missingIndex += 1) {
      const missingRef = missingElements[missingIndex];
      const missingInstance = await storeLoadByIdWithRefs(req.session.user, missingRef);
      // missingElements is already cache filtered
      if (isFullVisibleElement(missingInstance)) {
        const missingData = convertStoreToStix(missingInstance);
        const message = generateCreateMessage(missingInstance);
        const origin = { referer: EVENT_TYPE_DEPENDENCIES };
        const content = { data: missingData, message, origin, version: EVENT_CURRENT_VERSION };
        channel.sendEvent(eventId, EVENT_TYPE_CREATE, content);
        cache.set(missingData.id);
        await wait(channel.delay);
      }
    }
  };
  const resolveAndPublishDependencies = async (noDependencies, cache, channel, req, streamFilters, eventId, stix) => {
    // Resolving REFS
    await resolveAndPublishMissingRefs(cache, channel, req, streamFilters, eventId, stix);
    // Resolving CORE RELATIONS
    if (noDependencies === false) {
      const allRelCallback = async (relations) => {
        const notCachedRelations = relations.filter((m) => !cache.has(m.standard_id));
        for (let relIndex = 0; relIndex < notCachedRelations.length; relIndex += 1) {
          const relation = notCachedRelations[relIndex];
          const missingRelation = await storeLoadByIdWithRefs(req.session.user, relation.id);
          if (isFullVisibleElement(missingRelation)) {
            const stixRelation = convertStoreToStix(missingRelation);
            // Resolve refs
            await resolveAndPublishMissingRefs(cache, channel, req, streamFilters, eventId, stixRelation);
            // Publish relations
            const message = generateCreateMessage(missingRelation);
            const origin = { referer: EVENT_TYPE_DEPENDENCIES };
            const content = { data: stixRelation, message, origin, version: EVENT_CURRENT_VERSION };
            channel.sendEvent(eventId, EVENT_TYPE_CREATE, content);
            cache.set(stixRelation.id);
          }
        }
        await wait(channel.delay);
      };
      const allRelOptions = {
        elementId: stix.extensions[STIX_EXT_OCTI].id,
        indices: [READ_INDEX_STIX_CORE_RELATIONSHIPS, READ_INDEX_STIX_SIGHTING_RELATIONSHIPS, READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS],
        callback: allRelCallback
      };
      const relationTypes = [ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP];
      await listAllRelations(req.session.user, relationTypes, allRelOptions);
    }
  };
  const isFiltersEntityTypeMatch = (filters, type) => {
    let match = false;
    const fromAllTypes = [type, ...getParentTypes(type)];
    // eslint-disable-next-line no-restricted-syntax
    for (const filter of filters.entity_type.values) {
      if (fromAllTypes.includes(filter.id)) {
        match = true;
      }
    }
    return match;
  };
  const publishRelationDependencies = async (client, noDependencies, cache, filterCache, channel, req, streamFilters, element) => {
    const { user } = req.session;
    const { id: eventId, data: eventData } = element;
    const { type, data: stix, message } = eventData;
    const isRel = stix.type === 'relationship';
    const fromId = isRel ? stix.source_ref : stix.sighting_of_ref;
    const toId = isRel ? stix.target_ref : stix.where_sighted_refs[0];
    // Pre-filter by type to prevent resolutions as much as possible.
    const filters = adaptFiltersFrontendFormat(streamFilters);
    if (filters.entity_type && filters.entity_type.values.length > 0) {
      const fromType = isRel ? stix.extensions[STIX_EXT_OCTI].source_type : stix.extensions[STIX_EXT_OCTI].sighting_of_type;
      const matchingFrom = isFiltersEntityTypeMatch(filters, fromType);
      const toType = isRel ? stix.extensions[STIX_EXT_OCTI].target_type : stix.extensions[STIX_EXT_OCTI].where_sighted_types[0];
      const matchingTo = isFiltersEntityTypeMatch(filters, toType);
      if (!matchingFrom && !matchingTo) {
        return;
      }
    }
    const [fromStix, toStix] = await Promise.all([stixLoadById(user, fromId), stixLoadById(user, toId)]);
    if (fromStix && toStix) {
      // As we resolved at now, data can be deleted now.
      // We are force to resolve because stream cannot contain all dependencies on each event.
      const isFromVisible = await isInstanceMatchFilters(fromStix, streamFilters, filterCache);
      const isToVisible = await isInstanceMatchFilters(toStix, streamFilters, filterCache);
      if (isFromVisible || isToVisible) {
        await resolveAndPublishDependencies(noDependencies, cache, channel, req, streamFilters, eventId, stix);
        // await resolveAndPublishMissingRefs(cache, channel, req, streamFilters, eventId, stix);
        // From or to are visible, consider it as a dependency
        const origin = { referer: EVENT_TYPE_DEPENDENCIES };
        const content = { data: stix, message, origin, version: EVENT_CURRENT_VERSION };
        channel.sendEvent(eventId, type, content);
      }
    }
    client.sendHeartbeat(eventId);
  };
  const liveStreamHandler = async (req, res) => {
    const { id } = req.params;
    try {
      const { user } = req.session;
      const paramStartFrom = extractQueryParameter(req, 'from') || req.headers.from || req.headers['last-event-id'];
      let startFrom = (paramStartFrom === '0' || paramStartFrom === '0-0') ? FROM_START_STR : paramStartFrom;
      // Also handle event id with redis format stamp or stamp-index
      if (startFrom && startFrom.includes('-') && startFrom.split('-').length === 2) {
        const [timestamp] = startFrom.split('-');
        startFrom = utcDate(parseInt(timestamp, 10)).toISOString();
      }
      const recoverTo = extractQueryParameter(req, 'recover') || req.headers.recover || req.headers['recover-date'];
      const noDependencies = (req.query['no-dependencies'] || req.headers['no-dependencies']) === 'true';
      const noDelete = (req.query['listen-delete'] || req.headers['listen-delete']) === 'false';
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
        const collection = await findById(user, id);
        if (!collection) {
          res.statusMessage = 'This live stream doesnt exists';
          res.status(404).end();
          return;
        }
        const userGroups = await batchGroups(user, user.id, { batched: false, paginate: false });
        const collectionGroups = await streamCollectionGroups(user, collection);
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
      if (!isUserGlobalCapabilityGranted(user)) {
        // Access to the global live stream
        res.statusMessage = 'You are not authorized, please check your credentials';
        res.status(401).end();
        return;
      }
      // If no marking part of filtering are accessible for the user, return
      // It's better to prevent connection instead of having no events accessible
      if (streamFilters.markedBy) {
        const userMarkings = (user.allowed_marking || []).map((m) => m.internal_id);
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
      if (isNotEmptyField(recoverTo) && isEmptyField(startFrom)) {
        throw UnsupportedError('Recovery mode is only possible with a start date.');
      }
      // Init stream and broadcasting
      const userEmail = user.user_email;
      const filterCache = new LRU({ max: MAX_CACHE_SIZE, ttl: MAX_CACHE_TIME });
      const processor = createStreamProcessor(user, userEmail, async (elements, lastEventId) => {
        // Process the stream elements
        for (let index = 0; index < elements.length; index += 1) {
          const element = elements[index];
          const { id: eventId, event, data: eventData } = element;
          const { type, data: stix, version: eventVersion, context } = eventData;
          const isRelation = stix.type === 'relationship' || stix.type === 'sighting';
          // New stream support only v4+ events.
          const isCompatibleVersion = parseInt(eventVersion ?? '0', 10) >= 4;
          if (isCompatibleVersion) {
            // Check for inferences
            const isInferredData = stix.extensions[STIX_EXT_OCTI].is_inferred;
            if (!isInferredData || (isInferredData && withInferences)) {
              const isCurrentlyVisible = await isInstanceMatchFilters(stix, streamFilters, filterCache);
              if (type === EVENT_TYPE_UPDATE) {
                const { newDocument: previous } = jsonpatch.applyPatch(R.clone(stix), context.reverse_patch);
                const isPreviouslyVisible = await isInstanceMatchFilters(previous, streamFilters, filterCache);
                if (isPreviouslyVisible && !isCurrentlyVisible) { // No longer visible
                  client.sendEvent(eventId, EVENT_TYPE_DELETE, eventData);
                } else if (!isPreviouslyVisible && isCurrentlyVisible) { // Newly visible
                  await resolveAndPublishDependencies(noDependencies, cache, channel, req, streamFilters, eventId, stix);
                  client.sendEvent(eventId, EVENT_TYPE_CREATE, eventData);
                } else if (isCurrentlyVisible) { // Just an update
                  await resolveAndPublishDependencies(noDependencies, cache, channel, req, streamFilters, eventId, stix);
                  client.sendEvent(eventId, event, eventData);
                } else if (noDependencies === false && isRelation) { // Update but not visible
                  // In case of relationship publication, from or to can be related to something that
                  // is part of the filtering. We can consider this as dependencies
                  await publishRelationDependencies(client, noDependencies, cache, filterCache, channel, req, streamFilters, element);
                }
              } else if (isCurrentlyVisible) {
                if (type === EVENT_TYPE_DELETE) {
                  if (noDelete === false) {
                    client.sendEvent(eventId, event, eventData);
                  }
                } else { // Create and merge
                  await resolveAndPublishDependencies(noDependencies, cache, channel, req, streamFilters, eventId, stix);
                  client.sendEvent(eventId, event, eventData);
                }
              } else if (noDependencies === false && isRelation) { // Not an update and not visible
                // In case of relationship publication, from or to can be related to something that
                // is part of the filtering. We can consider this as dependencies
                await publishRelationDependencies(client, noDependencies, cache, filterCache, channel, req, streamFilters, element);
              }
            }
            // Delete eventual filtering cache
            filterCache.delete(stix.extensions[STIX_EXT_OCTI].id);
          }
          client.sendHeartbeat(eventId);
        }
        // Send the Heartbeat with last event id
        client.sendHeartbeat(lastEventId);
        // Wait to prevent flooding
        await wait(channel.delay);
      });
      await initBroadcasting(req, res, client, processor);
      // Start recovery if needed
      if (isNotEmptyField(recoverTo)) {
        // noinspection UnnecessaryLocalVariableJS
        const queryCallback = async (elements) => {
          for (let index = 0; index < elements.length; index += 1) {
            const { internal_id: elemId, standard_id: standardId } = elements[index];
            if (!cache.has(standardId)) { // With dependency resolving, id can be added in a previous iteration
              const instance = await storeLoadByIdWithRefs(user, elemId);
              if (isFullVisibleElement(instance)) {
                const stixData = convertStoreToStix(instance);
                const stixUpdatedAt = stixData.extensions[STIX_EXT_OCTI].updated_at;
                const eventId = `${utcDate(stixUpdatedAt).toDate().getTime()}-0`;
                if (channel.connected()) {
                  // publish missing dependencies if needed
                  await resolveAndPublishDependencies(noDependencies, cache, channel, req, streamFilters, eventId, stixData);
                  // publish element
                  if (!cache.has(stixData.id)) {
                    const message = generateCreateMessage(instance);
                    const origin = { referer: EVENT_TYPE_INIT };
                    const eventData = { data: stixData, message, origin, version: EVENT_CURRENT_VERSION };
                    channel.sendEvent(eventId, EVENT_TYPE_CREATE, eventData);
                    cache.set(stixData.id);
                  }
                } else {
                  return channel.connected();
                }
              }
            }
          }
          await wait(channel.delay);
          return channel.connected();
        };
        const queryOptions = convertFiltersToQueryOptions(streamFilters, { after: startFrom, before: recoverTo });
        queryOptions.callback = queryCallback;
        await elList(user, queryIndices, queryOptions);
      }
      // After recovery start the stream listening
      const streamStartDate = (recoverTo || startFrom) ? utcDate(recoverTo || startFrom) : undefined;
      logApp.info(`[STREAM] Listening stream ${id} from ${streamStartDate ?? 'live'}`);
      const startEventTime = streamStartDate && streamStartDate.isValid() ? `${streamStartDate.unix() * 1000}-0` : 'live';
      // noinspection ES6MissingAwait
      processor.start(startEventTime);
    } catch (e) {
      logApp.error(`Error executing live stream ${id}`, { error: e });
      res.statusMessage = `Error in stream ${id}: ${e.message}`;
      res.status(500).end();
    }
  };
  return {
    shutdown: () => {
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
