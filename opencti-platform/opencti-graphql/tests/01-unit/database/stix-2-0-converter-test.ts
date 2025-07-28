import { describe, it, expect } from 'vitest';
import { ENTITY_TYPE_TOOL, ENTITY_TYPE_VULNERABILITY } from '../../../src/schema/stixDomainObject';
import { EXPECTED_MALWARE, MALWARE_INSTANCE } from './instances-stix-2-0-converter/malware';
import { EXPECTED_REPORT, REPORT_INSTANCE } from './instances-stix-2-0-converter/containers/report';
import { EXPECTED_OBSERVED_DATA, OBSERVED_DATA_INSTANCE } from './instances-stix-2-0-converter/containers/observed-data';
import { EXPECTED_NOTE, NOTE_INSTANCE } from './instances-stix-2-0-converter/containers/note';
import { EXPECTED_OPINION, OPINION_INSTANCE } from './instances-stix-2-0-converter/containers/opinion';
import { EXPECTED_GROUPING, GROUPING_INSTANCE } from './instances-stix-2-0-converter/containers/grouping';
import { EXPECTED_FEEDBACK, FEEDBACK_INSTANCE } from './instances-stix-2-0-converter/containers/feedback';
import { EXPECTED_TASK, TASK_INSTANCE } from './instances-stix-2-0-converter/containers/task';
import { EXPECTED_IR, INCIDENT_RESPONSE_INSTANCE } from './instances-stix-2-0-converter/containers/incident_response';
import { EXPECTED_RFT, RFT_INSTANCE } from './instances-stix-2-0-converter/containers/case_rft';
import { EXPECTED_RFI, RFI_INSTANCE } from './instances-stix-2-0-converter/containers/case_rfi';
import { EXPECTED_TOOL, TOOL_INSTANCE } from './instances-stix-2-0-converter/tool';
import { EXPECTED_VULNERABILITY, INSTANCE_VULNERABILITY } from './instances-stix-2-0-converter/vulnerability';
import { convertGroupingToStix_2_0 } from '../../../src/modules/grouping/grouping-converter';
import { convertFeedbackToStix_2_0 } from '../../../src/modules/case/feedback/feedback-converter';
import { convertTaskToStix_2_0 } from '../../../src/modules/task/task-converter';
import { convertCaseIncidentToStix_2_0 } from '../../../src/modules/case/case-incident/case-incident-converter';
import { convertCaseRftToStix_2_0 } from '../../../src/modules/case/case-rft/case-rft-converter';
import { convertCaseRfiToStix_2_0 } from '../../../src/modules/case/case-rfi/case-rfi-converter';
import {
  convertToolToStix,
  convertVulnerabilityToStix,
  convertMalwareToStix,
  convertNoteToStix,
  convertObservedDataToStix,
  convertOpinionToStix,
  convertReportToStix
} from '../../../src/database/stix-2-0-converter';

describe('Stix 2.0 opencti converter', () => {
  it('should convert Malware', async () => {
    const result = convertMalwareToStix(MALWARE_INSTANCE);
    expect(result).toEqual(EXPECTED_MALWARE);
  });
  it('should convert Tool', async () => {
    const result = convertToolToStix(TOOL_INSTANCE);
    expect(result).toEqual(EXPECTED_TOOL);
  });
  it('should convert Vulnerability', async () => {
    const result = convertVulnerabilityToStix(INSTANCE_VULNERABILITY);
    expect(result).toEqual(EXPECTED_VULNERABILITY);
  });
  it('should convert Report', async () => {
    const result = convertReportToStix(REPORT_INSTANCE);
    expect(result).toEqual(EXPECTED_REPORT);
  });
  it('should convert Note', async () => {
    const result = convertNoteToStix(NOTE_INSTANCE);
    expect(result).toEqual(EXPECTED_NOTE);
  });
  it('should convert ObservedData', async () => {
    const result = convertObservedDataToStix(OBSERVED_DATA_INSTANCE);
    expect(result).toEqual(EXPECTED_OBSERVED_DATA);
  });
  it('should convert Opinion', async () => {
    const result = convertOpinionToStix(OPINION_INSTANCE);
    expect(result).toEqual(EXPECTED_OPINION);
  });
  it('should convert Grouping', async () => {
    const result = convertGroupingToStix_2_0(GROUPING_INSTANCE);
    expect(result).toEqual(EXPECTED_GROUPING);
  });
  it('should convert Feedback', async () => {
    const result = convertFeedbackToStix_2_0(FEEDBACK_INSTANCE);
    expect(result).toEqual(EXPECTED_FEEDBACK);
  });
  it('should convert Task', async () => {
    const result = convertTaskToStix_2_0(TASK_INSTANCE);
    expect(result).toEqual(EXPECTED_TASK);
  });
  it('should convert Incident Response', async () => {
    const result = convertCaseIncidentToStix_2_0(INCIDENT_RESPONSE_INSTANCE);
    expect(result).toEqual(EXPECTED_IR);
  });
  it('should convert Case RFI', async () => {
    const result = convertCaseRfiToStix_2_0(RFI_INSTANCE);
    expect(result).toEqual(EXPECTED_RFI);
  });
  it('should convert Case RFT', async () => {
    const result = convertCaseRftToStix_2_0(RFT_INSTANCE);
    expect(result).toEqual(EXPECTED_RFT);
  });
});
