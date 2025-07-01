import { describe, it, expect } from 'vitest';
import {
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_MALWARE
} from '../../../src/schema/stixDomainObject';
import {
  convertMalwareToStix,
  convertNoteToStix,
  convertObservedDataToStix,
  convertOpinionToStix,
  convertReportToStix,
  convertTypeToStix2Type
} from '../../../src/database/stix-2-0-converter';
import { EXPECTED_MALWARE, MALWARE_INSTANCE } from './instances-stix-2-0-converter/malware';
import { EXPECTED_REPORT, REPORT_INSTANCE } from './instances-stix-2-0-converter/containers/report';
import { EXPECTED_OBSERVED_DATA, OBSERVED_DATA_INSTANCE } from './instances-stix-2-0-converter/containers/observed-data';
import { EXPECTED_NOTE, NOTE_INSTANCE } from './instances-stix-2-0-converter/containers/note';
import { EXPECTED_OPINION, OPINION_INSTANCE } from './instances-stix-2-0-converter/containers/opinion';
import { convertGroupingToStix_2_0 } from '../../../src/modules/grouping/grouping-converter';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../../../src/modules/grouping/grouping-types';
import { EXPECTED_GROUPING, GROUPING_INSTANCE } from './instances-stix-2-0-converter/containers/grouping';

describe('Stix 2.0 opencti converter', () => {
  it('should convert Malware', async () => {
    const result = convertMalwareToStix(MALWARE_INSTANCE, ENTITY_TYPE_MALWARE);
    expect(result).toEqual(EXPECTED_MALWARE);
  });
  it('should convert Report', async () => {
    const result = convertReportToStix(REPORT_INSTANCE, ENTITY_TYPE_CONTAINER_REPORT);
    expect(result).toEqual(EXPECTED_REPORT);
  });
  it('should convert Note', async () => {
    const result = convertNoteToStix(NOTE_INSTANCE, ENTITY_TYPE_CONTAINER_NOTE);
    expect(result).toEqual(EXPECTED_NOTE);
  });
  it('should convert ObservedData', async () => {
    const result = convertObservedDataToStix(OBSERVED_DATA_INSTANCE, ENTITY_TYPE_CONTAINER_OBSERVED_DATA);
    expect(result).toEqual(EXPECTED_OBSERVED_DATA);
  });
  it('should convert Opinion', async () => {
    const result = convertOpinionToStix(OPINION_INSTANCE, ENTITY_TYPE_CONTAINER_OPINION);
    expect(result).toEqual(EXPECTED_OPINION);
  });
  it('should convert Grouping', async () => {
    const result = convertGroupingToStix_2_0(GROUPING_INSTANCE, ENTITY_TYPE_CONTAINER_GROUPING);
    expect(result).toEqual(EXPECTED_GROUPING);
  });
});

describe('convertTypeToStix2Type tests', () => {
  it('should return type', async () => {
    const types = [
      'Identity',
      'Location',
      'Threat-Actor',
      'StixFile',
      'Case-Incident',
      'Feedback',
      'Case-Rfi',
      'Case-Rft',
      'Task',
      'Data-Component',
      'Data-Source',
      'stix-sighting-relationship',
      'stix-core-relationship'
    ];
    const expectedTypes = [
      'identity',
      'location',
      'threat-actor',
      'file',
      'x-opencti-case-incident',
      'x-opencti-feedback',
      'x-opencti-case-rfi',
      'x-opencti-case-rft',
      'x-opencti-task',
      'x-mitre-data-component',
      'x-mitre-data-source',
      'sighting',
      'relationship'
    ];
    const result = types.map((type) => convertTypeToStix2Type(type));
    expect(result).toEqual(expectedTypes);
  });
});
