import * as R from 'ramda';
import conf, { basePath, logApp } from '../config/conf';
import { authenticateUserFromRequest, STREAMAPI } from '../domain/user';
import { createStreamProcessor } from '../database/redis';
import { generateInternalId } from '../schema/identifier';
import { findById } from '../domain/stream';
import {
  EVENT_TYPE_CREATE,
  EVENT_TYPE_DELETE,
  EVENT_TYPE_MERGE,
  EVENT_TYPE_SYNC,
  EVENT_TYPE_UPDATE,
} from '../database/rabbitmq';
import { stixLoadById } from '../database/middleware';
import { convertFiltersToQueryOptions } from '../domain/taxii';
import { elList } from '../database/elasticSearch';
import { isEmptyField, isNotEmptyField, READ_INDEX_STIX_META_OBJECTS, READ_STIX_INDICES } from '../database/utils';
import { buildStixData } from '../database/stix';
import { generateInternalType, getParentTypes } from '../schema/schemaUtils';
import { BYPASS, isBypassUser } from '../utils/access';
import { adaptFiltersFrontendFormat, TYPE_FILTER } from '../utils/filtering';
import { rebuildInstanceBeforePatch } from '../utils/patch';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';

let heartbeat;
export const MIN_LIVE_STREAM_EVENT_VERSION = 2;
const KEEP_ALIVE_INTERVAL_MS = 20000;
const broadcastClients = {};

const MARKING_FILTER = 'markedBy';
const LABEL_FILTER = 'labelledBy';
const CREATOR_FILTER = 'createdBy';
const SCORE_FILTER = 'x_opencti_score';
const DETECTION_FILTER = 'x_opencti_detection';
const CONFIDENCE_FILTER = 'confidence';
const REVOKED_FILTER = 'revoked';
const PATTERN_FILTER = 'pattern_type';

const EVENT_ADD = 'add';
const EVENT_DEL = 'del';
const EVENT_REP = 'replace';
const cleanCancelledAction = (eventsDifferential) => {
  const remaining = [];
  // for (let diffIndex = 0; diffIndex < eventsDifferential.length; diffIndex += 1) {
  const data = eventsDifferential[0];
  const { action, key, val } = data;
  const reverseAction = action === EVENT_ADD ? EVENT_DEL : EVENT_ADD;
  // Looking for reverse actions in the next steps
  let findReversedActionIndex = -1;
  const differentialTable = [];
  for (let nextActions = 1; nextActions < eventsDifferential.length; nextActions += 1) {
    const nextElem = eventsDifferential[nextActions];
    const isReversed = nextElem.action === reverseAction && nextElem.key === key && nextElem.val === val;
    if (isReversed && findReversedActionIndex === -1) {
      findReversedActionIndex = nextActions;
    } else {
      differentialTable.push(nextElem);
    }
  }
  // Find the reverse action
  if (findReversedActionIndex === -1) {
    // If no reverse action, keep the action and check the rest of the table.
    remaining.push(data);
  }
  if (differentialTable.length > 0) {
    remaining.push(...cleanCancelledAction(differentialTable));
  }
  return remaining;
};
const computeAggregatePatch = (events) => {
  const eventsDifferential = [];
  const updateEvents = events.filter((e) => e.topic === EVENT_TYPE_UPDATE || e.topic === EVENT_TYPE_MERGE);
  for (let index = 0; index < updateEvents.length; index += 1) {
    const updateEvent = updateEvents[index];
    const action = updateEvent.data.data.x_opencti_patch;
    if (action?.add) {
      const addActionsEntries = Object.entries(action.add);
      for (let addIndex = 0; addIndex < addActionsEntries.length; addIndex += 1) {
        const [key, values] = addActionsEntries[addIndex];
        const vals = values.map((v) => ({ action: EVENT_ADD, key, val: v.value, src: EVENT_ADD, patch: action })); // `${ADD}${ACTION_SPLIT}${key}${v}`);
        eventsDifferential.push(...vals);
      }
    }
    if (action?.remove) {
      const delActionsEntries = Object.entries(action.remove);
      for (let delIndex = 0; delIndex < delActionsEntries.length; delIndex += 1) {
        const [key, values] = delActionsEntries[delIndex];
        const vals = values.map((v) => ({ action: EVENT_DEL, key, val: v.value, src: EVENT_DEL, patch: action })); // `${DEL}${ACTION_SPLIT}${key}${v}`);
        eventsDifferential.push(...vals);
      }
    }
    if (action?.replace) {
      const replaceActionsEntries = Object.entries(action.replace);
      for (let replaceIndex = 0; replaceIndex < replaceActionsEntries.length; replaceIndex += 1) {
        const [key, values] = replaceActionsEntries[replaceIndex];
        const { current, previous } = values;
        if (Array.isArray(current)) {
          const previousValues = previous || [];
          const deleted = previousValues.filter((f) => !current.includes(f));
          eventsDifferential.push(
            ...deleted.map((v) => ({ action: EVENT_DEL, key, val: v, src: EVENT_REP, patch: action }))
          );
          const added = current.filter((f) => !previousValues.includes(f));
          eventsDifferential.push(
            ...added.map((v) => ({ action: EVENT_ADD, key, val: v, src: EVENT_REP, patch: action }))
          );
        } else {
          eventsDifferential.push({ action: EVENT_DEL, key, val: previous || '', src: EVENT_REP, patch: action });
          eventsDifferential.push({ action: EVENT_ADD, key, val: current, src: EVENT_REP, patch: action });
        }
      }
    }
  }
  // Compute the final diff
  if (eventsDifferential.length === 0) return {};
  const impactFullActions = cleanCancelledAction(eventsDifferential);
  if (impactFullActions.length === 0) {
    // Finally nothing happens :)
    return {};
  }
  // Now we need to recompute the actions diff from impacts
  const patchElements = [];
  const actionsPerKey = R.groupBy((e) => e.key, impactFullActions);
  const keyEntries = Object.entries(actionsPerKey);
  for (let keyIndex = 0; keyIndex < keyEntries.length; keyIndex += 1) {
    const [, vals] = keyEntries[keyIndex];
    const diff = R.mergeAll(vals.map((v) => v.patch));
    patchElements.push(diff);
  }
  const mergeDeepAll = R.unapply(R.reduce(R.mergeDeepRight, {}));
  return mergeDeepAll(...patchElements);
};
const isElementEvolved = (openctiId, events) => {
  // 01. Handle create/delete differential
  // - (CREATION) Create => YES
  // - (RECREATION) Delete - Create = Not possible because x_opencti_id will be different
  // - (DELETION) Delete => YES
  // - (INSTANT DELETION) Create - Delete = NO
  const creationEvents = events.filter((e) => e.topic === EVENT_TYPE_CREATE);
  const isCreatedElement = creationEvents.length > 0;
  const deletionEvents = events.filter((e) => e.topic === EVENT_TYPE_DELETE);
  const isDeleteElement = deletionEvents.length > 0;
  // If created but deleted in the same time frame, considering nothing happen
  if (isCreatedElement && isDeleteElement) {
    return undefined;
  }
  const eventId = R.last(events).id;
  // If is a creation or a deletion, considering as an evolution
  const patch = computeAggregatePatch(events);
  if (isCreatedElement) {
    return { id: openctiId, eventId, topic: EVENT_TYPE_CREATE, patch };
  }
  if (isDeleteElement) {
    const content = R.head(deletionEvents).data.data;
    return { id: openctiId, eventId, topic: EVENT_TYPE_DELETE, content, patch };
  }
  // 02. Handle update differential
  // In this case, we only take care about element evolution
  if (R.isEmpty(patch)) {
    return undefined;
  }
  return { id: openctiId, eventId, topic: EVENT_TYPE_UPDATE, patch };
};
export const computeEventsDiff = (elements) => {
  // If merge elements are inside, we need to flatten the deletion
  const flattenElements = [];
  for (let elemIndex = 0; elemIndex < elements.length; elemIndex += 1) {
    const element = elements[elemIndex];
    if (element.topic === EVENT_TYPE_MERGE) {
      const instanceData = element.data.data;
      const mergedDeleted = instanceData.x_opencti_context.sources.map((s) => {
        return {
          id: element.id,
          topic: EVENT_TYPE_DELETE,
          data: { markings: s.object_marking_refs, origin: element.origin, data: s, version: element.version },
        };
      });
      flattenElements.push(...mergedDeleted);
    }
    flattenElements.push(element);
  }
  // Need to compute the diff change
  const groupedById = R.groupBy((e) => e.data.data.x_opencti_id, flattenElements);
  const entries = Object.entries(groupedById);
  const retainElements = [];
  for (let i = 0; i < entries.length; i += 1) {
    const [k, v] = entries[i];
    const isElementEvolve = isElementEvolved(k, v);
    if (isElementEvolve) {
      retainElements.push(isElementEvolve);
    }
  }
  return R.sort((a, b) => {
    const [timeA] = a.id.split('-');
    const [timeB] = b.id.split('-');
    return parseInt(timeA, 10) - parseInt(timeB, 10);
  }, retainElements);
};

export const isInstanceMatchFilters = (instance, filters) => {
  // Pre filters transformation to handle specific frontend format
  const adaptedFilters = adaptFiltersFrontendFormat(filters);
  // User is granted but we still need to apply filters if needed
  const filterEntries = Object.entries(adaptedFilters);
  for (let index = 0; index < filterEntries.length; index += 1) {
    const [type, { operator, values }] = filterEntries[index];
    // Markings filtering
    if (type === MARKING_FILTER) {
      // event must have one of this marking
      const markingIds = (instance.object_marking_refs || []).map((l) => l.x_opencti_internal_id);
      const found = values.map((v) => v.id).some((r) => markingIds.includes(r));
      if (!found) return false;
    }
    // Entity type filtering
    if (type === TYPE_FILTER) {
      const instanceType = generateInternalType(instance);
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
      if (!found) return false;
    }
    // Creator filtering
    if (type === CREATOR_FILTER) {
      const creatorIds = (instance.created_by_ref || []).map((l) => l.x_opencti_internal_id);
      const found = values.map((v) => v.id).some((r) => creatorIds.includes(r));
      if (!found) return false;
    }
    // Labels filtering
    if (type === LABEL_FILTER) {
      const labelsIds = (instance.labels || []).map((l) => l.x_opencti_internal_id);
      const found = values.map((v) => v.id).some((r) => labelsIds.includes(r));
      if (!found) return false;
    }
    // Boolean filtering
    if (type === REVOKED_FILTER || type === DETECTION_FILTER) {
      const { id } = R.head(values);
      const found = (id === 'true') === instance[type];
      if (!found) return false;
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
      if (!found) return false;
    }
    // String filtering
    if (type === PATTERN_FILTER) {
      const { id } = R.head(values);
      const found = id === instance[type];
      if (!found) return false;
    }
  }
  return true;
};

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
    expirationTime: channel.expirationTime,
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
  const auth = await authenticateUserFromRequest(req);
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

const createSeeMiddleware = () => {
  createHeartbeatProcessor();
  const initBroadcasting = async (req, res, client, processor) => {
    const broadcasterInfo = await processor.info();
    req.on('close', () => {
      req.finished = true;
      delete broadcastClients[client.id];
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
      user: req.session.user,
      userId: req.userId,
      expirationTime: req.expirationTime,
      allowed_marking: req.allowed_marking,
      capabilities: req.capabilities,
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
    const { client } = createSseChannel(req, res);
    const processor = createStreamProcessor(req.session.user, req.session.user.user_email, async (elements) => {
      for (let index = 0; index < elements.length; index += 1) {
        const { id: eventId, topic, data } = elements[index];
        client.sendEvent(eventId, topic, data);
      }
    });
    try {
      await initBroadcasting(req, res, client, processor);
      await processor.start(req.query.from || req.headers['last-event-id']);
    } catch (err) {
      res.status(500);
      res.json({ error: 'Error accessing stream (empty stream or redis client connection problem)' });
    }
  };
  const buildProcessingMessages = (streamFilters, user, elements) => {
    const processingMessages = [];
    for (let messageIndex = 0; messageIndex < elements.length; messageIndex += 1) {
      const element = elements[messageIndex];
      const { data, version } = element.data;
      if (parseInt(version, 10) >= MIN_LIVE_STREAM_EVENT_VERSION) {
        const isGranted = isEventGranted(element.data, user);
        // Pre filter for entity_type if needed
        const filterTypes = streamFilters?.entity_type || [];
        const instanceType = generateInternalType(data);
        const instanceAllTypes = [instanceType, ...getParentTypes(instanceType)];
        let isValid = false;
        if (filterTypes.length === 0) {
          isValid = true;
        } else {
          // eslint-disable-next-line no-restricted-syntax
          for (const filter of filterTypes) {
            if (instanceAllTypes.includes(filter.id)) {
              isValid = true;
            }
          }
        }
        if (isGranted && isValid) {
          processingMessages.push(element);
        }
      }
    }
    return processingMessages;
  };
  const filteredStreamHandler = async (req, res) => {
    const { id } = req.params;
    const startFrom = req.query.from || req.headers['last-event-id'];
    const compactDepth = parseInt(req.headers['live-depth-compact'] || conf.get('redis:live_depth_compact'), 10);
    const collection = await findById(req.session.user, id);
    if (!collection) {
      res.status(500);
      res.json({ error: 'This live stream doesnt exists' });
      return;
    }
    const streamFilters = JSON.parse(collection.filters);
    // If no marking part of filtering are accessible for the user, return
    // Its better to prevent connection instead of having no events accessible
    if (streamFilters.markedBy) {
      const userMarkings = (req.session.user.allowed_marking || []).map((m) => m.internal_id);
      const filterMarkings = (streamFilters.markedBy || []).map((m) => m.id);
      const isUserHaveAccess = filterMarkings.some((m) => userMarkings.includes(m));
      if (!isUserHaveAccess) {
        res.status(500);
        res.json({ error: 'You need to have access to specific markings for this live stream' });
        return;
      }
    }
    // Create channel.
    const { channel, client } = createSseChannel(req, res);
    const processor = createStreamProcessor(
      req.session.user,
      req.session.user.user_email,
      async (elements) => {
        // We need to build all elements that have change during the last call
        const processingMessages = buildProcessingMessages(streamFilters, req.session.user, elements);
        // Need to compute the diff change
        const diffElements = computeEventsDiff(processingMessages);
        for (let index = 0; index < diffElements.length; index += 1) {
          const { id: diffId, eventId, topic, content, patch } = diffElements[index];
          if (topic === EVENT_TYPE_CREATE) {
            const currentInstance = await stixLoadById(req.session.user, diffId);
            // Could be null because of user markings restriction
            if (currentInstance) {
              const createdInstance = buildStixData(currentInstance, { patchGeneration: true });
              const isMatchFilters = isInstanceMatchFilters(createdInstance, streamFilters);
              if (isMatchFilters) {
                const data = buildStixData(currentInstance, { clearEmptyValues: true });
                if (isNotEmptyField(data.x_opencti_patch)) {
                  data.x_opencti_patch = patch;
                }
                const markings = data.object_marking_refs || [];
                client.sendEvent(eventId, EVENT_TYPE_CREATE, { data, markings });
              }
            }
          }
          if (topic === EVENT_TYPE_DELETE) {
            const data = content;
            const markings = data.object_marking_refs || [];
            if (isNotEmptyField(data.x_opencti_patch)) {
              data.x_opencti_patch = patch;
            }
            client.sendEvent(eventId, EVENT_TYPE_DELETE, { data, markings });
          }
          if (topic === EVENT_TYPE_UPDATE) {
            const currentInstance = await stixLoadById(req.session.user, diffId);
            // Could be null because of markings restriction
            if (currentInstance) {
              const current = buildStixData(currentInstance, { patchGeneration: true });
              const beforePatch = rebuildInstanceBeforePatch(current, patch);
              const isBeforePatchVisible = isInstanceMatchFilters(beforePatch, streamFilters);
              const isCurrentVisible = isInstanceMatchFilters(current, streamFilters);
              const data = buildStixData(currentInstance);
              const markings = data.object_marking_refs || [];
              data.x_opencti_patch = patch;
              // If updatedInstance pass the filtering but not initialInstance -> creation event
              if (isCurrentVisible && !isBeforePatchVisible) {
                client.sendEvent(eventId, EVENT_TYPE_CREATE, { data, markings });
              }
              // If initialInstance pass the filtering but not updatedInstance -> deletion event
              if (isBeforePatchVisible && !isCurrentVisible) {
                client.sendEvent(eventId, EVENT_TYPE_DELETE, { data, markings });
              }
              if (isBeforePatchVisible && isCurrentVisible) {
                client.sendEvent(eventId, topic, { data, markings });
              }
            }
          }
        }
        if (elements.length > 0 && channel.connected()) {
          channel.sendEvent(R.last(elements).id, EVENT_TYPE_SYNC, null);
        }
      },
      compactDepth
    );
    try {
      await initBroadcasting(req, res, client, processor);
      // If empty start date, stream all results corresponding to the filters
      if (isEmptyField(startFrom)) {
        const queryOptions = convertFiltersToQueryOptions(streamFilters);
        // noinspection UnnecessaryLocalVariableJS
        const queryCallback = async (elements) => {
          for (let index = 0; index < elements.length; index += 1) {
            const { internal_id: elemId } = elements[index];
            const instance = await stixLoadById(req.session.user, elemId);
            const data = buildStixData(instance, { clearEmptyValues: true });
            const markings = data.object_marking_refs || [];
            if (channel.connected()) {
              const eventId = utcDate(data.updated_at).toDate().getTime();
              const message = generateCreateMessage(instance);
              channel.sendEvent(eventId, EVENT_TYPE_CREATE, { data, markings, message, version });
            } else {
              return false;
            }
          }
          return channel.connected();
        };
        queryOptions.callback = queryCallback;
        await elList(req.session.user, [READ_INDEX_STIX_META_OBJECTS, ...READ_STIX_INDICES], queryOptions);
        // We need to sent a special event to mark the end of init with the current timestamp
        const catchId = `${new Date().getTime()}-0`;
        channel.sendEvent(catchId, EVENT_TYPE_SYNC, { message: 'Catchup done' });
      }
      // After start to stream the live.
      await processor.start(startFrom);
    } catch (e) {
      res.status(500);
      res.json({ error: 'Error accessing stream (empty stream or redis client connection problem)' });
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
    },
  };
};

export default createSeeMiddleware;
