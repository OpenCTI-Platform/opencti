import { describe, it, expect } from 'vitest';
import {
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_MALWARE
} from '../../../src/schema/stixDomainObject';
import {
  convertIncidentToStix,
  convertMalwareToStix,
  convertNoteToStix,
  convertObservedDataToStix,
  convertOpinionToStix,
  convertReportToStix,
  convertSightingToStix
} from '../../../src/database/stix-2-0-converter';
import { EXPECTED_MALWARE, MALWARE_INSTANCE } from './instances-stix-2-0-converter/malware';
import { EXPECTED_REPORT, REPORT_INSTANCE } from './instances-stix-2-0-converter/containers/report';
import { EXPECTED_OBSERVED_DATA, OBSERVED_DATA_INSTANCE } from './instances-stix-2-0-converter/containers/observed-data';
import { EXPECTED_NOTE, NOTE_INSTANCE } from './instances-stix-2-0-converter/containers/note';
import { EXPECTED_OPINION, OPINION_INSTANCE } from './instances-stix-2-0-converter/containers/opinion';
import { convertGroupingToStix_2_0 } from '../../../src/modules/grouping/grouping-converter';
import { EXPECTED_GROUPING, GROUPING_INSTANCE } from './instances-stix-2-0-converter/containers/grouping';
import { EXPECTED_FEEDBACK, FEEDBACK_INSTANCE } from './instances-stix-2-0-converter/containers/feedback';
import { convertFeedbackToStix_2_0 } from '../../../src/modules/case/feedback/feedback-converter';
import { ENTITY_TYPE_CONTAINER_TASK } from '../../../src/modules/task/task-types';
import { convertTaskToStix_2_0 } from '../../../src/modules/task/task-converter';
import { EXPECTED_TASK, TASK_INSTANCE } from './instances-stix-2-0-converter/containers/task';
import { EXPECTED_IR, INCIDENT_RESPONSE_INSTANCE } from './instances-stix-2-0-converter/containers/incident_response';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../../../src/modules/case/case-incident/case-incident-types';
import { convertCaseIncidentToStix_2_0 } from '../../../src/modules/case/case-incident/case-incident-converter';
import { convertCaseRftToStix_2_0 } from '../../../src/modules/case/case-rft/case-rft-converter';
import { EXPECTED_RFT, RFT_INSTANCE } from './instances-stix-2-0-converter/containers/case_rft';
import { ENTITY_TYPE_CONTAINER_CASE_RFT } from '../../../src/modules/case/case-rft/case-rft-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../../../src/modules/case/case-rfi/case-rfi-types';
import { EXPECTED_RFI, RFI_INSTANCE } from './instances-stix-2-0-converter/containers/case_rfi';
import { convertCaseRfiToStix_2_0 } from '../../../src/modules/case/case-rfi/case-rfi-converter';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../../../src/modules/grouping/grouping-types';
import { ENTITY_TYPE_CONTAINER_FEEDBACK } from '../../../src/modules/case/feedback/feedback-types';
import { EXPECTED_INCIDENT, INCIDENT_INSTANCE } from './instances-stix-2-0-converter/SDOs/incident';
import { EXPECTED_SIGHTING, SIGHTING_INSTANCE } from './instances-stix-2-0-converter/sightings';

describe('Stix 2.0 opencti converter', () => {
  // SDOs
  it('should convert Malware', async () => {
    const result = convertMalwareToStix(MALWARE_INSTANCE, ENTITY_TYPE_MALWARE);
    expect(result).toEqual(EXPECTED_MALWARE);
  });
  it('should convert Incident', async () => {
    const result = convertIncidentToStix(INCIDENT_INSTANCE, ENTITY_TYPE_INCIDENT);
    expect(result).toEqual(EXPECTED_INCIDENT);
  });
  // Containers
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
  it('should convert Feedback', async () => {
    const result = convertFeedbackToStix_2_0(FEEDBACK_INSTANCE, ENTITY_TYPE_CONTAINER_FEEDBACK);
    expect(result).toEqual(EXPECTED_FEEDBACK);
  });
  it('should convert Task', async () => {
    const result = convertTaskToStix_2_0(TASK_INSTANCE, ENTITY_TYPE_CONTAINER_TASK);
    expect(result).toEqual(EXPECTED_TASK);
  });
  it('should convert Incident Response', async () => {
    const result = convertCaseIncidentToStix_2_0(INCIDENT_RESPONSE_INSTANCE, ENTITY_TYPE_CONTAINER_CASE_INCIDENT);
    expect(result).toEqual(EXPECTED_IR);
  });
  it('should convert Case RFI', async () => {
    const result = convertCaseRfiToStix_2_0(RFI_INSTANCE, ENTITY_TYPE_CONTAINER_CASE_RFI);
    expect(result).toEqual(EXPECTED_RFI);
  });
  it('should convert Case RFT', async () => {
    const result = convertCaseRftToStix_2_0(RFT_INSTANCE, ENTITY_TYPE_CONTAINER_CASE_RFT);
    expect(result).toEqual(EXPECTED_RFT);
  });
  // SROs
  it('should convert StixSightingRelationship', async () => {
    const result = convertSightingToStix(SIGHTING_INSTANCE);
    expect(result).toEqual(EXPECTED_SIGHTING);
  });
});
