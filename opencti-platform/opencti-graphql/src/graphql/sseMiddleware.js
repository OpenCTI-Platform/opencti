import * as R from 'ramda';
import * as jsonpatch from 'fast-json-patch';
import { Promise } from 'bluebird';
import LRU from 'lru-cache';
import conf, { basePath, logApp } from '../config/conf';
import { authenticateUserFromRequest, batchGroups, STREAMAPI } from '../domain/user';
import { createStreamProcessor, EVENT_CURRENT_VERSION, STREAM_BATCH_TIME } from '../database/redis';
import { generateInternalId, generateStandardId } from '../schema/identifier';
import { findById, streamCollectionGroups } from '../domain/stream';
import { stixLoadById, stixLoadByIds, storeLoadByIdWithRefs } from '../database/middleware';
import { elList, ES_MAX_CONCURRENCY, MAX_SPLIT } from '../database/engine';
import {
  EVENT_TYPE_CREATE,
  EVENT_TYPE_DELETE,
  EVENT_TYPE_DEPENDENCIES,
  EVENT_TYPE_INIT,
  EVENT_TYPE_UPDATE,
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
import { BYPASS, executionContext, isUserCanAccessStixElement } from '../utils/access';
import { FROM_START_STR, utcDate } from '../utils/format';
import { stixRefsExtractor } from '../schema/stixEmbeddedRelationship';
import {
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP,
  buildRefRelationKey,
  ENTITY_TYPE_CONTAINER
} from '../schema/general';
import { convertStoreToStix } from '../database/stix-converter';
import { UnsupportedError } from '../config/errors';
import { convertFiltersToQueryOptions, isStixMatchFilters } from '../utils/filtering';
import { getParentTypes } from '../schema/schemaUtils';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import { listAllRelations, listEntities } from '../database/middleware-loader';
import { RELATION_OBJECT } from '../schema/stixMetaRelationship';

const broadcastClients = {};
const queryIndices = [...READ_STIX_INDICES, READ_INDEX_STIX_META_OBJECTS];
const DEFAULT_LIVE_STREAM = 'live';
const ONE_HOUR = 1000 * 60 * 60;
const MAX_CACHE_TIME = (conf.get('app:live_stream:cache_max_time') ?? 1) * ONE_HOUR;
const MAX_CACHE_SIZE = conf.get('app:live_stream:cache_max_size') ?? 5000;

const createBroadcastClient = (channel) => {
  let lastHeartbeat;
  return {
    id: channel.id,
    userId: channel.userId,
    expirationTime: channel.expirationTime,
    setChannelDelay: (d) => channel.setDelay(d),
    close: () => channel.close(),
    sendEvent: (eventId, topic, event) => {
      channel.sendEvent(eventId, topic, event);
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
    const executeContext = executionContext('stream_authenticate');
    const auth = await authenticateUserFromRequest(executeContext, req, res);
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
    if (paramData && Array.isArray(paramData) && paramData.length > 0) {
      return paramData.at(0);
    }
    return paramData;
  };
  const isUserGlobalCapabilityGranted = (user) => {
    const capabilityControl = (s) => s.name === BYPASS || s.name === STREAMAPI;
    return R.find(capabilityControl, user.capabilities || []) !== undefined;
  };
  const resolveMissingReferences = async (context, req, missingRefs, cache) => {
    const refsToResolve = missingRefs.filter((m) => !cache.has(m));
    const missingElements = [];
    if (refsToResolve.length > 0) {
      // Resolve missing element standard ids
      const missingIds = [];
      const groupsOfRefsToResolve = R.splitEvery(MAX_SPLIT, refsToResolve);
      const missingRefsResolver = async (refs) => {
        const idsOpts = { ids: refs, connectionFormat: false };
        const findMissing = await elList(context, req.session.user, queryIndices, idsOpts);
        missingIds.push(...R.uniq(findMissing.map((f) => f.standard_id)));
      };
      await Promise.map(groupsOfRefsToResolve, missingRefsResolver, { concurrency: ES_MAX_CONCURRENCY });
      missingElements.push(...missingIds);
      // Resolve every missing element
      const uniqueIds = R.uniq(missingIds);
      const resolvedElements = await stixLoadByIds(context, req.session.user, uniqueIds);
      const parentRefs = resolvedElements.map((r) => stixRefsExtractor(r, generateStandardId)).flat();
      if (parentRefs.length > 0) {
        const newMissing = await resolveMissingReferences(context, req, parentRefs, cache);
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
      const sessionUser = req.session.user;
      const context = executionContext('raw_stream');
      if (!isUserGlobalCapabilityGranted(sessionUser)) {
        res.statusMessage = 'You are not authorized, please check your credentials';
        res.status(401).end();
        return;
      }
      const { client } = createSseChannel(req, res);
      const processor = createStreamProcessor(sessionUser, sessionUser.user_email, async (elements, lastEventId) => {
        // Process the event messages
        for (let index = 0; index < elements.length; index += 1) {
          const { id: eventId, event, data } = elements[index];
          const instanceAccessible = await isUserCanAccessStixElement(context, sessionUser, data.data);
          if (instanceAccessible) {
            client.sendEvent(eventId, event, data);
          }
        }
        // Send the Heartbeat with last event id
        client.sendHeartbeat(lastEventId);
      });
      await initBroadcasting(req, res, client, processor);
      const paramStartFrom = extractQueryParameter(req, 'from') || req.headers['last-event-id'];
      const startStreamId = convertParameterToStreamId(paramStartFrom);
      await processor.start(startStreamId);
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
  const resolveAndPublishMissingRefs = async (context, cache, channel, req, eventId, stixData) => {
    const refs = stixRefsExtractor(stixData, generateStandardId);
    const missingElements = await resolveMissingReferences(context, req, refs, cache);
    for (let missingIndex = 0; missingIndex < missingElements.length; missingIndex += 1) {
      const missingRef = missingElements[missingIndex];
      const missingInstance = await storeLoadByIdWithRefs(context, req.session.user, missingRef);
      if (missingInstance) {
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
  const resolveAndPublishDependencies = async (context, noDependencies, cache, channel, req, eventId, stix) => {
    // Resolving REFS
    await resolveAndPublishMissingRefs(context, cache, channel, req, eventId, stix);
    // Resolving CORE RELATIONS
    if (noDependencies === false) {
      const allRelCallback = async (relations) => {
        const notCachedRelations = relations.filter((m) => !cache.has(m.standard_id));
        for (let relIndex = 0; relIndex < notCachedRelations.length; relIndex += 1) {
          const relation = notCachedRelations[relIndex];
          const missingRelation = await storeLoadByIdWithRefs(context, req.session.user, relation.id);
          if (missingRelation) {
            const stixRelation = convertStoreToStix(missingRelation);
            // Resolve refs
            await resolveAndPublishMissingRefs(context, cache, channel, req, eventId, stixRelation);
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
      await listAllRelations(context, req.session.user, relationTypes, allRelOptions);
    }
  };
  const isFiltersEntityTypeMatch = (filters, type) => {
    let match = false;
    const matches = [];
    const fromAllTypes = [type, ...getParentTypes(type)];
    // eslint-disable-next-line no-restricted-syntax
    for (const filter of filters.entity_type.values) {
      // consider the operator
      if (filter.operator === 'not_eq') {
        if (!fromAllTypes.includes(filter.id)) {
          matches.push(true);
        } else {
          matches.push(false);
        }
      } else if (fromAllTypes.includes(filter.id)) { // operator = 'eq'
        matches.push(true);
      } else {
        matches.push(false);
      }
      // consider the filterMode
      if (filter.filterMode === 'and') {
        if (!matches.includes(false)) {
          match = true;
        }
      } else if (matches.includes(true)) { // filterMode = 'or'
        match = true;
      }
    }
    return match;
  };
  const publishRelationDependencies = async (context, client, noDependencies, cache, channel, req, streamFilters, element) => {
    const { user } = req.session;
    const { id: eventId, data: eventData } = element;
    const { type, data: stix, message } = eventData;
    const isRel = stix.type === 'relationship';
    const fromId = isRel ? stix.source_ref : stix.sighting_of_ref;
    const toId = isRel ? stix.target_ref : stix.where_sighted_refs[0];
    // Pre-filter by type to prevent resolutions as much as possible.
    if (streamFilters.entity_type && streamFilters.entity_type.values.length > 0) {
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
      const isFromVisible = await isStixMatchFilters(context, user, fromStix, streamFilters);
      const isToVisible = await isStixMatchFilters(context, user, toStix, streamFilters);
      if (isFromVisible || isToVisible) {
        await resolveAndPublishDependencies(context, noDependencies, cache, channel, req, eventId, stix);
        // From or to are visible, consider it as a dependency
        const origin = { referer: EVENT_TYPE_DEPENDENCIES };
        const content = { data: stix, message, origin, version: EVENT_CURRENT_VERSION };
        channel.sendEvent(eventId, type, content);
      }
    }
    client.sendHeartbeat(eventId);
  };
  const convertParameterToDate = (param) => {
    if (!param) {
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
    if (!param) {
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
      const cache = new LRU({ max: MAX_CACHE_SIZE, ttl: MAX_CACHE_TIME });
      const { user } = req.session;
      // If stream is starting after, we need to use the main database to catchup
      const context = executionContext('live_stream');
      const paramStartFrom = extractQueryParameter(req, 'from') || req.headers.from || req.headers['last-event-id'];
      const startIsoDate = convertParameterToDate(paramStartFrom);
      const startStreamId = convertParameterToStreamId(paramStartFrom);
      const recoverToParameter = extractQueryParameter(req, 'recover') || req.headers.recover || req.headers['recover-date'];
      const recoverIsoDate = convertParameterToDate(recoverToParameter);
      const recoverStreamId = convertParameterToStreamId(recoverToParameter);
      const noDependencies = (req.query['no-dependencies'] || req.headers['no-dependencies']) === 'true';
      const publishDependencies = noDependencies === false;
      const noDelete = (req.query['listen-delete'] || req.headers['listen-delete']) === 'false';
      const publishDeletion = noDelete === false;
      const withInferences = (req.query['with-inferences'] || req.headers['with-inferences']) === 'true';
      if (withInferences) {
        queryIndices.push(READ_INDEX_INFERRED_ENTITIES, READ_INDEX_INFERRED_RELATIONSHIPS);
      }
      // Build filters
      let streamFilters = {};
      if (id !== DEFAULT_LIVE_STREAM) {
        const collection = await findById(context, user, id);
        if (!collection) {
          res.statusMessage = 'This live stream doesnt exists';
          res.status(404).end();
          return;
        }
        const userGroups = await batchGroups(context, user, user.id, { batched: false, paginate: false });
        const collectionGroups = await streamCollectionGroups(context, user, collection);
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
      // If empty start date, stream all results corresponding to the filters
      // We need to fetch from this start date until the stream existence
      if (isNotEmptyField(recoverIsoDate) && isEmptyField(startIsoDate)) {
        throw UnsupportedError('Recovery mode is only possible with a start date.');
      }
      // Init stream and broadcasting
      const userEmail = user.user_email;
      const processor = createStreamProcessor(user, userEmail, async (elements, lastEventId) => {
        // Process the stream elements
        for (let index = 0; index < elements.length; index += 1) {
          const element = elements[index];
          const { id: eventId, event, data: eventData } = element;
          const { type, data: stix, version: eventVersion, context: evenContext } = eventData;
          const isRelation = stix.type === 'relationship' || stix.type === 'sighting';
          // New stream support only v4+ events.
          const isCompatibleVersion = parseInt(eventVersion ?? '0', 10) >= 4;
          if (isCompatibleVersion) {
            // Check for inferences
            const isInferredData = stix.extensions[STIX_EXT_OCTI].is_inferred;
            if (!isInferredData || (isInferredData && withInferences)) {
              const isCurrentlyVisible = await isStixMatchFilters(context, user, stix, streamFilters);
              if (type === EVENT_TYPE_UPDATE) {
                const { newDocument: previous } = jsonpatch.applyPatch(R.clone(stix), evenContext.reverse_patch);
                const isPreviouslyVisible = await isStixMatchFilters(context, user, previous, streamFilters);
                if (isPreviouslyVisible && !isCurrentlyVisible) { // No longer visible
                  client.sendEvent(eventId, EVENT_TYPE_DELETE, eventData);
                } else if (!isPreviouslyVisible && isCurrentlyVisible) { // Newly visible
                  await resolveAndPublishDependencies(context, noDependencies, cache, channel, req, eventId, stix);
                  client.sendEvent(eventId, EVENT_TYPE_CREATE, eventData);
                } else if (isCurrentlyVisible) { // Just an update
                  await resolveAndPublishDependencies(context, noDependencies, cache, channel, req, eventId, stix);
                  client.sendEvent(eventId, event, eventData);
                } else if (isRelation && publishDependencies) { // Update but not visible - relation type
                  // In case of relationship publication, from or to can be related to something that
                  // is part of the filtering. We can consider this as dependencies
                  await publishRelationDependencies(context, client, noDependencies, cache, channel, req, streamFilters, element);
                } else { // Update but not visible - entity type
                  // Entity can be part of a container that is authorized by the filters
                  // If it's the case, the element must be published
                  const elementInternalId = stix.extensions[STIX_EXT_OCTI].id;
                  const filters = [{ key: [buildRefRelationKey(RELATION_OBJECT)], values: [elementInternalId] }];
                  const args = { connectionFormat: false, filters };
                  const containers = await listEntities(context, user, [ENTITY_TYPE_CONTAINER], args);
                  let isContainerMatching = false;
                  for (let containerIndex = 0; containerIndex < containers.length; containerIndex += 1) {
                    const container = containers[containerIndex];
                    const stixContainer = convertStoreToStix(container);
                    const containerMatch = await isStixMatchFilters(context, user, stixContainer, streamFilters);
                    if (containerMatch) {
                      isContainerMatching = true;
                      break;
                    }
                  }
                  // At least one container is matching the filter, so publishing the event
                  if (isContainerMatching) {
                    await resolveAndPublishMissingRefs(context, cache, channel, req, eventId, stix);
                    client.sendEvent(eventId, event, eventData);
                  }
                }
              } else if (isCurrentlyVisible) {
                if (type === EVENT_TYPE_DELETE) {
                  if (publishDeletion) {
                    client.sendEvent(eventId, event, eventData);
                  }
                } else { // Create and merge
                  await resolveAndPublishDependencies(context, noDependencies, cache, channel, req, eventId, stix);
                  client.sendEvent(eventId, event, eventData);
                }
              } else if (isRelation && publishDependencies) { // Not an update and not visible
                // In case of relationship publication, from or to can be related to something that
                // is part of the filtering. We can consider this as dependencies
                await publishRelationDependencies(context, client, noDependencies, cache, channel, req, streamFilters, element);
              }
            }
          }
          client.sendHeartbeat(eventId);
        }
        // Send the Heartbeat with last event id
        client.sendHeartbeat(lastEventId);
        // Wait to prevent flooding
        await wait(channel.delay);
      });
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
          for (let index = 0; index < elements.length; index += 1) {
            const { internal_id: elemId, standard_id: standardId } = elements[index];
            if (!cache.has(standardId)) { // With dependency resolving, id can be added in a previous iteration
              const instance = await storeLoadByIdWithRefs(context, user, elemId);
              if (instance) {
                const stixData = convertStoreToStix(instance);
                const stixUpdatedAt = stixData.extensions[STIX_EXT_OCTI].updated_at;
                const eventId = `${utcDate(stixUpdatedAt).toDate().getTime()}-0`;
                if (channel.connected()) {
                  // publish missing dependencies if needed
                  await resolveAndPublishDependencies(context, noDependencies, cache, channel, req, eventId, stixData);
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
        const queryOptions = await convertFiltersToQueryOptions(context, streamFilters, { after: startIsoDate, before: recoverIsoDate });
        queryOptions.callback = queryCallback;
        await elList(context, user, queryIndices, queryOptions);
      }
      // noinspection ES6MissingAwait
      processor.start(isRecoveryMode ? recoverStreamId : startStreamId);
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
