import { describe, it, expect } from 'vitest';
import '../../../src/modules/index';
import { convertStoreToStix_2_1 } from '../../../src/database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';
import type { StixMalware, StixThreatActor, StixIntrusionSet, StixIncident, StixIdentity } from '../../../src/types/stix-2-1-sdo';
import type { StixEvent } from '../../../src/modules/event/event-types';
import { MALWARE_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/arsenal/malware';
import { THREAT_ACTOR_GROUP_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/threats/threat-actor-group';
import { INTRUSION_SET_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/threats/intrusion-set';
import { INCIDENT_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/threats/incident';
import { ORGANIZATION_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/entities/organization';
import { EVENT_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/entities/event';

// Regression test for #17752: Malware, Threat-Actor-Group and Intrusion-Set
// used to omit x_opencti_score from their STIX 2.1 extensions, breaking the
// "Score has changed" playbook filter for these entity types.
describe('STIX 2.1 converter - score propagation', () => {
  it('should expose x_opencti_score on Malware', () => {
    const stix = convertStoreToStix_2_1({ ...MALWARE_INSTANCE, x_opencti_score: 42 } as any) as StixMalware;
    expect((stix.extensions[STIX_EXT_OCTI] as Record<string, any>).score).toBe(42);
  });

  it('should expose x_opencti_score on Threat-Actor-Group', () => {
    const stix = convertStoreToStix_2_1({ ...THREAT_ACTOR_GROUP_INSTANCE, x_opencti_score: 55 } as any) as StixThreatActor;
    expect((stix.extensions[STIX_EXT_OCTI] as Record<string, any>).score).toBe(55);
  });

  it('should expose x_opencti_score on Intrusion-Set', () => {
    const stix = convertStoreToStix_2_1({ ...INTRUSION_SET_INSTANCE, x_opencti_score: 63 } as any) as StixIntrusionSet;
    expect((stix.extensions[STIX_EXT_OCTI] as Record<string, any>).score).toBe(63);
  });

  it('should expose x_opencti_score on Incident', () => {
    const stix = convertStoreToStix_2_1({ ...INCIDENT_INSTANCE, x_opencti_score: 71 } as any) as StixIncident;
    expect((stix.extensions[STIX_EXT_OCTI] as Record<string, any>).score).toBe(71);
  });

  it('should expose x_opencti_score on Organization', () => {
    const stix = convertStoreToStix_2_1({ ...ORGANIZATION_INSTANCE, x_opencti_score: 88 } as any) as StixIdentity;
    expect((stix.extensions[STIX_EXT_OCTI] as Record<string, any>).score).toBe(88);
  });

  it('should expose x_opencti_score on Event', () => {
    const stix = convertStoreToStix_2_1({ ...EVENT_INSTANCE, x_opencti_score: 33 } as any) as StixEvent;
    expect((stix.extensions[STIX_EXT_OCTI] as Record<string, any>).score).toBe(33);
  });
});
