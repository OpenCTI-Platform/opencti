import { expect } from 'vitest';
import { EventSource } from 'eventsource';
import * as R from 'ramda';
import { validate as isUuid } from 'uuid';
import { ADMIN_USER, generateBasicAuth, testContext } from './testQuery';
import { isStixId } from '../../src/schema/schemaUtils';
import { isStixRelationship } from '../../src/schema/stixRelationship';
import { STIX_EXT_OCTI } from '../../src/types/stix-2-1-extensions';
import { EVENT_TYPE_UPDATE } from '../../src/database/utils';
import { internalLoadById } from '../../src/database/middleware-loader';
import type { UpdateEvent } from '../../src/types/event';
import type { StixObject } from '../../src/types/stix-2-1-common';
import type { RelationExtension, StixRelation } from '../../src/types/stix-2-1-sro';

export const fetchStreamEvents = (uri: string, { from }: { from?: string } = {}) => {
  return new Promise((resolve, reject) => {
    let eventNumber = 0;
    const events: { type: string, data: string, lastEventId: string, origin: string }[] = [];
    const customFetch: typeof fetch = (input, init) => {
      return fetch(input, {
        ...init,
        headers: {
          ...(init?.headers ?? {}),
          Authorization: generateBasicAuth(),
          ...(from ? {'Last-Event-ID': from} : {}),
        },
      });
    };
    const es = new EventSource(uri, { fetch: customFetch });
    const closeEventSource = () => {
      es.close();
      resolve(events);
    };
    const handleEvent = (type: string) => (event: MessageEvent) => {
      const { data, lastEventId, origin } = event;
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
    es.addEventListener('create', (event) => handleEvent('create')(event));
    es.addEventListener('update', (event) => handleEvent('update')(event));
    es.addEventListener('merge', (event) => handleEvent('merge')(event));
    es.addEventListener('delete', (event) => handleEvent('delete')(event));
    es.onerror = (err) => reject(err);
  });
};

export const checkInstanceDiff = async (loaded: Record<string, unknown>, rebuilt: Record<string, unknown>, idLoader = internalLoadById) => {
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
        const data = await idLoader(testContext, ADMIN_USER, rebuildAttr as string);
        rebuildAttr = data.standard_id;
      }
      if (attributeKey.endsWith('_refs')) {
        const data = await Promise.all((rebuildAttr as string[]).map(async (r) => idLoader(testContext, ADMIN_USER, r)));
        rebuildAttr = data.map((r) => r.standard_id);
      }
      if (Array.isArray(fetchAttr) && Array.isArray(rebuildAttr)) {
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

export const checkStreamData = (type: string, data: StixObject, context: UpdateEvent['context']) => {
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
    const relationship = data as StixRelation;
    const relationshipExt = octiExt as RelationExtension;
    expect(relationship.relationship_type).toBeDefined();
    expect(isStixRelationship(relationship.relationship_type)).toBeTruthy();
    expect(relationship.source_ref).toBeDefined();
    expect(isStixId(relationship.source_ref)).toBeTruthy();
    expect(relationshipExt.source_ref).toBeDefined();
    expect(isUuid(relationshipExt.source_ref)).toBeTruthy();
    expect(relationship.target_ref).toBeDefined();
    expect(isStixId(relationship.target_ref)).toBeTruthy();
    expect(relationshipExt.target_ref).toBeDefined();
    expect(isUuid(relationshipExt.target_ref)).toBeTruthy();
  }
  if (octiExt.stix_ids) {
    octiExt.stix_ids.forEach((m) => {
      expect(isStixId(m)).toBeTruthy();
    });
  }
};

export const checkStreamGenericContent = (type: string, dataEvent: UpdateEvent) => {
  const { data, message, context } = dataEvent;
  expect(message.includes(', , ,')).toBeFalsy();
  expect(message.includes('undefined')).toBeFalsy();
  expect(message.includes('[object Object]')).toBeFalsy();
  expect(message).not.toBeNull();
  checkStreamData(type, data, context);
};
