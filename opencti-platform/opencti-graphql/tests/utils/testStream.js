import { expect } from 'vitest';
import { EventSource } from 'eventsource';
import * as R from 'ramda';
import { validate as isUuid } from 'uuid';
import { ADMIN_USER, generateBasicAuth, testContext } from './testQuery';
import { isStixId } from '../../src/schema/schemaUtils';
import { isStixRelationship } from '../../src/schema/stixRelationship';
import { STIX_EXT_OCTI } from '../../src/types/stix-2-1-extensions';
import { EVENT_TYPE_UPDATE, wait } from '../../src/database/utils';
import { internalLoadById } from '../../src/database/middleware-loader';
import { fetchStreamInfo } from '../../src/database/stream/stream-handler';
import { logApp } from '../../src/config/conf';

const compareStreamIds = (a, b) => {
  const [aTime, aSeq] = a.split('-').map(Number);
  const [bTime, bSeq] = b.split('-').map(Number);
  return aTime === bTime ? aSeq - bSeq : aTime - bTime;
};

// Late writers (connectors, workers) can still push events after the previous test files:
// wait until nothing was appended to the raw stream for stableTime, then return its last event id.
export const waitForStableStream = async (stableTime = 10000, pollInterval = 1000) => {
  let { lastEventId } = await fetchStreamInfo();
  let stableSince = Date.now();
  while (Date.now() - stableSince < stableTime) {
    await wait(pollInterval);
    const info = await fetchStreamInfo();
    if (info.lastEventId !== lastEventId) {
      lastEventId = info.lastEventId;
      stableSince = Date.now();
    }
  }
  return lastEventId;
};

// Without untilEventId, the stream is closed after idleTimeout ms without a new event.
// With untilEventId, it is closed as soon as this event, or a heartbeat past it, is received,
// unless the stream has grown meanwhile; the idle timeout stays as a fallback.
export const fetchStreamEvents = (uri, { from, untilEventId, idleTimeout = 30000 } = {}) => {
  const extraHeaders = { authorization: generateBasicAuth(), 'last-event-id': from };
  const fetchWithHeaders = (url, init) => fetch(url, { ...init, headers: { ...init.headers, ...extraHeaders } });
  return new Promise((resolve, reject) => {
    let eventNumber = 0;
    const events = [];
    const es = new EventSource(uri, { fetch: fetchWithHeaders });
    let closed = false;
    const closeEventSource = () => {
      if (!closed) {
        closed = true;
        es.close();
        resolve(events);
      }
    };
    let targetEventId = untilEventId;
    const closeIfTargetReached = async (lastEventId) => {
      if (!targetEventId || !lastEventId || compareStreamIds(lastEventId, targetEventId) < 0) {
        return;
      }
      try {
        const info = await fetchStreamInfo();
        if (compareStreamIds(info.lastEventId, lastEventId) <= 0) {
          closeEventSource();
        } else {
          targetEventId = info.lastEventId;
        }
      } catch (err) {
        // The next event or heartbeat retries, the idle timeout closes the stream otherwise
        logApp.warn('[TEST] Fail to fetch the stream info', { cause: err });
      }
    };
    const handleEvent = (event) => {
      if (closed) {
        return;
      }
      const { type, data, lastEventId, origin } = event;
      eventNumber += 1;
      const currentEventNumber = eventNumber;
      events.push({ type, data: JSON.parse(data), lastEventId, origin });
      // If no new event for idleTimeout ms, stop the processing
      setTimeout(() => {
        if (currentEventNumber === eventNumber) {
          closeEventSource();
        }
      }, idleTimeout);
      void closeIfTargetReached(lastEventId);
    };
    es.addEventListener('create', (event) => handleEvent(event));
    es.addEventListener('update', (event) => handleEvent(event));
    es.addEventListener('merge', (event) => handleEvent(event));
    es.addEventListener('delete', (event) => handleEvent(event));
    es.addEventListener('heartbeat', (event) => void closeIfTargetReached(event.lastEventId));
    es.addEventListener('error', (err) => reject(err));
  });
};

export const checkInstanceDiff = async (loaded, rebuilt, idLoader = internalLoadById) => {
  const attributes = Object.keys(loaded);
  const diffElements = [];
  for (let attrIndex = 0; attrIndex < attributes.length; attrIndex += 1) {
    const attributeKey = attributes[attrIndex];
    if (attributeKey === 'extensions' || attributeKey === 'revoked' || attributeKey === 'lang' || attributeKey === 'modified') {
      // TODO Add a specific check
      // Currently some attributes are valuated by default or different by design
    } else {
      const fetchAttr = loaded[attributeKey];
      let rebuildAttr = rebuilt[attributeKey];
      if (attributeKey.endsWith('_ref')) {
        const data = await idLoader(testContext, ADMIN_USER, rebuildAttr);
        rebuildAttr = data.standard_id;
      }
      if (attributeKey.endsWith('_refs')) {
        const data = await Promise.all(rebuildAttr.map(async (r) => idLoader(testContext, ADMIN_USER, r)));
        rebuildAttr = data.map((r) => r.standard_id);
      }
      if (Array.isArray(fetchAttr)) {
        if (fetchAttr.length !== rebuildAttr.length) {
          diffElements.push({ attributeKey, fetchAttr: fetchAttr.length, rebuildAttr: rebuildAttr.length });
        } else if (attributeKey.endsWith('_refs')) {
          const fetch = fetchAttr.sort().filter((f) => !f.startsWith('relationship--'));
          const rebuild = rebuildAttr.sort().filter((f) => !f.startsWith('relationship--'));
          if (!R.equals(fetch.sort(), rebuild.sort())) {
            diffElements.push({ attributeKey, fetchAttr, rebuildAttr });
          }
        } else if (!R.equals(fetchAttr.sort(), rebuildAttr.sort())) {
          diffElements.push({ attributeKey, fetchAttr, rebuildAttr });
        }
      } else if (!R.equals(fetchAttr, rebuildAttr)) {
        diffElements.push({ attributeKey, fetchAttr, rebuildAttr });
      }
    }
  }
  return diffElements;
};

export const checkStreamData = (type, data, context) => {
  expect(data.id).toBeDefined();
  expect(isStixId(data.id)).toBeTruthy();
  const octiExt = data.extensions[STIX_EXT_OCTI];
  expect(octiExt.id).toBeDefined();
  expect(octiExt.type).toBeDefined();
  expect(octiExt.created_at).toBeDefined();
  expect(isUuid(octiExt.id)).toBeTruthy();
  expect(data.type).toBeDefined();
  if (type === EVENT_TYPE_UPDATE) {
    expect(context.patch).toBeDefined();
    expect(context.patch.length).toBeGreaterThan(0);
    expect(context.reverse_patch).toBeDefined();
    expect(context.reverse_patch.length).toBeGreaterThan(0);
  }
  if (data.type === 'relationship') {
    expect(data.relationship_type).toBeDefined();
    expect(isStixRelationship(data.relationship_type)).toBeTruthy();
    expect(data.source_ref).toBeDefined();
    expect(isStixId(data.source_ref)).toBeTruthy();
    expect(octiExt.source_ref).toBeDefined();
    expect(isUuid(octiExt.source_ref)).toBeTruthy();
    expect(data.target_ref).toBeDefined();
    expect(isStixId(data.target_ref)).toBeTruthy();
    expect(octiExt.target_ref).toBeDefined();
    expect(isUuid(octiExt.target_ref)).toBeTruthy();
  }
  if (octiExt.stix_ids) {
    octiExt.stix_ids.forEach((m) => {
      expect(isStixId(m)).toBeTruthy();
    });
  }
};

export const checkStreamGenericContent = (type, dataEvent) => {
  const { data, message, context } = dataEvent;
  expect(message.includes(', , ,')).toBeFalsy();
  expect(message.includes('undefined')).toBeFalsy();
  expect(message.includes('[object Object]')).toBeFalsy();
  expect(message).not.toBeNull();
  checkStreamData(type, data, context);
};
