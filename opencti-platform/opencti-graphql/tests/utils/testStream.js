import EventSource from 'eventsource';
import * as R from 'ramda';
import { validate as isUuid } from 'uuid';
import { ADMIN_USER, generateBasicAuth } from './testQuery';
import { internalLoadById } from '../../src/database/middleware';
import { isStixId } from '../../src/schema/schemaUtils';
import { EVENT_TYPE_UPDATE } from '../../src/database/rabbitmq';
import { isStixRelationship } from '../../src/schema/stixRelationship';
import { STIX_EXT_OCTI } from '../../src/types/stix-extensions';

export const fetchStreamEvents = (uri, { from } = {}) => {
  const opts = {
    headers: { authorization: generateBasicAuth(), 'last-event-id': from },
  };
  return new Promise((resolve, reject) => {
    let eventNumber = 0;
    const events = [];
    const es = new EventSource(uri, opts);
    const closeEventSource = () => {
      es.close();
      resolve(events);
    };
    const handleEvent = (event) => {
      const { type, data, lastEventId, origin } = event;
      eventNumber += 1;
      const currentEventNumber = eventNumber;
      events.push({ type, data: JSON.parse(data), lastEventId, origin });
      // If no new event for 5 secs, stop the processing
      setTimeout(() => {
        if (currentEventNumber === eventNumber) {
          closeEventSource();
        }
      }, 5000);
    };
    es.addEventListener('create', (event) => handleEvent(event));
    es.addEventListener('update', (event) => handleEvent(event));
    es.addEventListener('merge', (event) => handleEvent(event));
    es.addEventListener('delete', (event) => handleEvent(event));
    es.onerror = (err) => reject(err);
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
        const data = await idLoader(ADMIN_USER, rebuildAttr);
        rebuildAttr = data.standard_id;
      }
      if (attributeKey.endsWith('_refs')) {
        const data = await Promise.all(rebuildAttr.map(async (r) => idLoader(ADMIN_USER, r)));
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
