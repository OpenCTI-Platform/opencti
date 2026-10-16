import { describe, expect, it } from 'vitest';
import '../../../src/modules/index';
import { convertStoreToStix_2_1 } from '../../../src/database/stix-2-1-converter';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_TIMELINE } from '../../../src/types/stix-2-1-extensions';
import { ATTRIBUTE_TIMELINE_EXCHANGE } from '../../../src/modules/timeline/timeline-types';
import { INCIDENT_RESPONSE_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/containers/incident_response';

const exchange = {
  events: [{
    id: 'timeline-event--6b0cbf59-1fd4-4b5a-9c55-1f2f4f5b8d11',
    event_time: '2026-02-05T10:30:00.000Z',
    lane: 'response',
    kind: 'containment',
    title: 'Hosts isolated by the SOC',
    object_marking_refs: [],
  }],
  annotations: [],
};

describe('STIX 2.1 converter - incident and case timeline extension', () => {
  it('should carry the analyst contributions of the timeline in a property extension of the container', () => {
    const stix = convertStoreToStix_2_1({ ...INCIDENT_RESPONSE_INSTANCE, [ATTRIBUTE_TIMELINE_EXCHANGE]: exchange } as any) as any;
    const extension = stix.extensions[STIX_EXT_OCTI_TIMELINE];
    expect(extension.extension_type).toEqual('property-extension');
    expect(extension.events.map((event: { title: string }) => event.title)).toEqual(['Hosts isolated by the SOC']);
    // The platform extension is kept next to it
    expect(stix.extensions[STIX_EXT_OCTI]).toBeDefined();
  });

  it('should not add the extension to a container without contributions', () => {
    const empty = convertStoreToStix_2_1({ ...INCIDENT_RESPONSE_INSTANCE, [ATTRIBUTE_TIMELINE_EXCHANGE]: { events: [], annotations: [] } } as any) as any;
    expect(empty.extensions[STIX_EXT_OCTI_TIMELINE]).toBeUndefined();
    const none = convertStoreToStix_2_1(INCIDENT_RESPONSE_INSTANCE as any) as any;
    expect(none.extensions[STIX_EXT_OCTI_TIMELINE]).toBeUndefined();
  });
});
