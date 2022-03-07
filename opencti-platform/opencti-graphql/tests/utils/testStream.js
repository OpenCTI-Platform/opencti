import EventSource from 'eventsource';
import * as R from 'ramda';
import { validate as isUuid } from 'uuid';
import { ADMIN_USER, generateBasicAuth } from './testQuery';
import { internalLoadById } from '../../src/database/middleware';
import { isStixId } from '../../src/schema/schemaUtils';
import { EVENT_TYPE_UPDATE } from '../../src/database/rabbitmq';
import { isStixRelationship } from '../../src/schema/stixRelationship';
import { isEmptyField } from '../../src/database/utils';

export const fetchStreamEvents = (uri, { from } = {}) => {
  const opts = {
    headers: { authorization: generateBasicAuth(), 'last-event-id': from },
  };
  return new Promise((resolve, reject) => {
    let lastEventTime = null;
    const events = [];
    const es = new EventSource(uri, opts);
    const closeEventSource = () => {
      es.close();
      resolve(events);
    };
    const handleEvent = (event) => {
      const { type, data, lastEventId, origin } = event;
      const [time] = lastEventId.split('-');
      const currentTime = parseInt(time, 10);
      lastEventTime = currentTime;
      events.push({ type, data: JSON.parse(data), lastEventId, origin });
      // If no new event for 5 secs, stop the processing
      setTimeout(() => {
        if (lastEventTime === currentTime) {
          closeEventSource();
        }
      }, 5000);
    };
    es.addEventListener('update', (event) => handleEvent(event));
    es.addEventListener('create', (event) => handleEvent(event));
    es.addEventListener('merge', (event) => handleEvent(event));
    es.addEventListener('delete', (event) => handleEvent(event));
    es.addEventListener('sync', () => closeEventSource());
    es.onerror = (err) => reject(err);
  });
};

export const checkInstanceDiff = async (loaded, rebuilt, idLoader = internalLoadById) => {
  const attributes = Object.keys(loaded);
  const diffElements = [];
  for (let attrIndex = 0; attrIndex < attributes.length; attrIndex += 1) {
    const attributeKey = attributes[attrIndex];
    if (attributeKey === 'x_opencti_id'
      || attributeKey === 'x_opencti_created_at'
      || attributeKey === 'x_opencti_workflow_id'
      || attributeKey === 'extensions'
      || attributeKey === 'revoked'
      || attributeKey === 'lang'
    ) {
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

export const checkStreamData = (type, data) => {
  expect(data.id).toBeDefined();
  expect(isStixId(data.id)).toBeTruthy();
  expect(data.x_opencti_id).toBeDefined();
  expect(data.x_opencti_type).toBeDefined();
  expect(data.x_opencti_created_at).toBeDefined();
  expect(isUuid(data.x_opencti_id)).toBeTruthy();
  expect(data.type).toBeDefined();
  if (type === EVENT_TYPE_UPDATE) {
    expect(data.x_opencti_patch).toBeDefined();
    if (data.x_opencti_patch.add) {
      Object.entries(data.x_opencti_patch.add).forEach(([k, v]) => {
        expect(k.includes('undefined')).toBeFalsy();
        expect(k.includes('[object Object]')).toBeFalsy();
        expect(k.endsWith('_ref')).toBeFalsy();
        expect(v.length).toBeGreaterThan(0);
        v.forEach((value) => {
          expect(isEmptyField(value)).toBeFalsy();
        });
        if (k.endsWith('_refs')) {
          v.forEach((value) => {
            expect(value.value).toBeDefined();
            expect(value.x_opencti_id).toBeDefined();
          });
        }
      });
    }
    if (data.x_opencti_patch.remove) {
      Object.entries(data.x_opencti_patch.remove).forEach(([k, v]) => {
        expect(k.includes('undefined')).toBeFalsy();
        expect(k.includes('[object Object]')).toBeFalsy();
        expect(k.endsWith('_ref')).toBeFalsy();
        expect(v.length).toBeGreaterThan(0);
        v.forEach((value) => {
          expect(isEmptyField(value)).toBeFalsy();
        });
        if (k.endsWith('_refs')) {
          v.forEach((value) => {
            expect(value.value).toBeDefined();
            expect(value.x_opencti_id).toBeDefined();
          });
        }
      });
    }
    if (data.x_opencti_patch.replace) {
      Object.entries(data.x_opencti_patch.replace).forEach(([k, v]) => {
        expect(k.includes('undefined')).toBeFalsy();
        expect(k.includes('[object Object]')).toBeFalsy();
        expect(v.current).toBeDefined();
        expect(v.previous).toBeDefined();
      });
    }
  }
  if (data.type === 'relationship') {
    expect(data.relationship_type).toBeDefined();
    expect(isStixRelationship(data.relationship_type)).toBeTruthy();
    expect(data.source_ref).toBeDefined();
    expect(isStixId(data.source_ref)).toBeTruthy();
    expect(data.x_opencti_source_ref).toBeDefined();
    expect(isUuid(data.x_opencti_source_ref)).toBeTruthy();
    expect(data.target_ref).toBeDefined();
    expect(isStixId(data.target_ref)).toBeTruthy();
    expect(data.x_opencti_target_ref).toBeDefined();
    expect(isUuid(data.x_opencti_target_ref)).toBeTruthy();
  }
  if (data.x_opencti_stix_ids) {
    data.x_opencti_stix_ids.forEach((m) => {
      expect(isStixId(m)).toBeTruthy();
    });
  }
};

export const checkStreamGenericContent = (type, dataEvent) => {
  const { data, markings, message } = dataEvent;
  expect(markings).toBeDefined();
  expect(message.includes('undefined')).toBeFalsy();
  expect(message.includes('[object Object]')).toBeFalsy();
  if (markings.length > 0) {
    markings.forEach((m) => {
      // Markings can have internal or stix depending on the loading.
      // To have the best performance, sometimes we use directly internal.
      expect(isUuid(m) || isStixId(m)).toBeTruthy();
    });
  }
  expect(message).not.toBeNull();
  checkStreamData(type, data);
};
