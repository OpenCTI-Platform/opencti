/**
 * Expected count of event by type is declared here.
 *
 * When doing any changes numbers in this file, please check that all services run without error on Drone.
 * - opencti-raw-start
 * - opencti-live-start
 * - opencti-direct-start
 * - opencti-restore-start
 *
 * If there is some missing entries, you can check txt files in test-result folder.
 */
import { VOCABULARY_NUMBERS } from '../11-sync/sync-utils';

export const testCreatedCounter: Record<string, number> = {};
testCreatedCounter.artifact = 4;
testCreatedCounter['attack-pattern'] = 22;
testCreatedCounter.campaign = 6;
testCreatedCounter['case-incident'] = 7;
testCreatedCounter['case-rfi'] = 9;
testCreatedCounter['case-rft'] = 1;
testCreatedCounter.channel = 1;
testCreatedCounter['course-of-action'] = 4;
testCreatedCounter.credential = 1;
testCreatedCounter['data-component'] = 2;
testCreatedCounter['data-source'] = 2;
testCreatedCounter['email-addr'] = 1;
testCreatedCounter.event = 2;
testCreatedCounter['external-reference'] = 17;
testCreatedCounter.feedback = 2;
testCreatedCounter.file = 10;
testCreatedCounter.grouping = 2;
testCreatedCounter.iccid = 4;
testCreatedCounter.identity = 58;
testCreatedCounter.imei = 3;
testCreatedCounter.imsi = 1;
testCreatedCounter.incident = 7;
testCreatedCounter.indicator = 64;
testCreatedCounter.infrastructure = 1;
testCreatedCounter['intrusion-set'] = 6;
testCreatedCounter['ipv4-addr'] = 1;
testCreatedCounter['kill-chain-phase'] = 3;
testCreatedCounter.label = 15;
testCreatedCounter.language = 1;
testCreatedCounter.location = 21;
testCreatedCounter['mac-addr'] = 1;
testCreatedCounter.malware = 63;
testCreatedCounter['malware-analysis'] = 3;
testCreatedCounter['marking-definition'] = 24;
testCreatedCounter.narrative = 1;
testCreatedCounter['network-traffic'] = 1;
testCreatedCounter.note = 6;
// 1 in the dataset + 2 created by observedData-domain-test
testCreatedCounter['observed-data'] = 3;
testCreatedCounter.opinion = 5;
testCreatedCounter.persona = 1;
testCreatedCounter['phone-number'] = 2;
testCreatedCounter['ssh-key'] = 1;
testCreatedCounter.relationship = 153;
testCreatedCounter.report = 55;
testCreatedCounter.sighting = 9;
testCreatedCounter.software = 2;
testCreatedCounter.task = 1;
testCreatedCounter['threat-actor'] = 33;
testCreatedCounter.tool = 5;
testCreatedCounter['tracking-number'] = 1;
testCreatedCounter.vocabulary = VOCABULARY_NUMBERS;
testCreatedCounter.vulnerability = 11;
testCreatedCounter['security-coverage'] = 24;
testCreatedCounter['security-coverage-result'] = 21;

export const testUpdatedCounter: Record<string, number> = {};
testUpdatedCounter['marking-definition'] = 2;
testUpdatedCounter.relationship = 24;
testUpdatedCounter.campaign = 7;
testUpdatedCounter.identity = 33;
testUpdatedCounter.malware = 20;
testUpdatedCounter.file = 19;
testUpdatedCounter['intrusion-set'] = 5;
testUpdatedCounter['data-component'] = 7;
testUpdatedCounter.location = 14;
testUpdatedCounter['attack-pattern'] = 3;
testUpdatedCounter['case-incident'] = 11;
testUpdatedCounter.feedback = 1;
testUpdatedCounter.report = 18;
testUpdatedCounter['course-of-action'] = 3;
testUpdatedCounter['data-source'] = 1;
testUpdatedCounter['external-reference'] = 1;
testUpdatedCounter.grouping = 3;
testUpdatedCounter.incident = 4;
testUpdatedCounter.indicator = 31;
testUpdatedCounter.label = 1;
testUpdatedCounter['malware-analysis'] = 3;
testUpdatedCounter.note = 3;
// Observed data is imported twice by the loader test: the second import is an upsert that increments number_seen (1)
// + 2 upserts in observedData-domain-test
testUpdatedCounter['observed-data'] = 3;
testUpdatedCounter.opinion = 6;
testUpdatedCounter['email-addr'] = 1;
testUpdatedCounter.event = 1;
testUpdatedCounter.persona = 1;
testUpdatedCounter['ssh-key'] = 1;
testUpdatedCounter['case-rfi'] = 5;
testUpdatedCounter['ipv4-addr'] = 4;
testUpdatedCounter.tool = 10;
// + 1 repair of a stale hits sighting in indicatorDeployment-test
testUpdatedCounter.sighting = 7;
testUpdatedCounter['threat-actor'] = 18;
testUpdatedCounter.vocabulary = 3;
testUpdatedCounter.vulnerability = 5;
testUpdatedCounter.iccid = 1;
testUpdatedCounter.imei = 1;
testUpdatedCounter.imsi = 1;
testUpdatedCounter['security-coverage'] = 1;

export const testMergedCounter: Record<string, number> = {};
testMergedCounter['threat-actor'] = 5;
testMergedCounter.identity = 1;
testMergedCounter.report = 3;
testMergedCounter.file = 3;
testMergedCounter.artifact = 1;
testMergedCounter['attack-pattern'] = 1;

export const testDeletedCounter: Record<string, number> = {};
testDeletedCounter.artifact = 3;
testDeletedCounter['attack-pattern'] = 17;
testDeletedCounter.campaign = 2;
testDeletedCounter['case-incident'] = 7;
testDeletedCounter['case-rfi'] = 9;
testDeletedCounter['case-rft'] = 1;
testDeletedCounter.channel = 1;
testDeletedCounter['course-of-action'] = 2;
testDeletedCounter['data-component'] = 2;
testDeletedCounter['data-source'] = 2;
testDeletedCounter['email-addr'] = 1;
testDeletedCounter.event = 2;
testDeletedCounter['external-reference'] = 1;
testDeletedCounter.feedback = 2;
testDeletedCounter.file = 6;
testDeletedCounter.grouping = 2;
testDeletedCounter.identity = 41;
testDeletedCounter.incident = 6;
testDeletedCounter.indicator = 36;
testDeletedCounter.infrastructure = 1;
testDeletedCounter['intrusion-set'] = 5;
testDeletedCounter['ipv4-addr'] = 1;
testDeletedCounter.label = 2;
testDeletedCounter.language = 1;
testDeletedCounter.location = 16;
testDeletedCounter['mac-addr'] = 1;
testDeletedCounter.malware = 36;
testDeletedCounter['malware-analysis'] = 2;
testDeletedCounter['marking-definition'] = 13;
testDeletedCounter.narrative = 1;
testDeletedCounter['network-traffic'] = 1;
testDeletedCounter.note = 5;
testDeletedCounter['observed-data'] = 2; // created and deleted by observedData-domain-test
testDeletedCounter.opinion = 4;
testDeletedCounter.persona = 1;
testDeletedCounter['phone-number'] = 2;
testDeletedCounter.relationship = 4;
testDeletedCounter.report = 46;
testDeletedCounter.sighting = 4;
testDeletedCounter['ssh-key'] = 1;
testDeletedCounter.task = 1;
testDeletedCounter['threat-actor'] = 20;
testDeletedCounter.tool = 5;
testDeletedCounter.vulnerability = 5;
testDeletedCounter.software = 1;
testDeletedCounter.iccid = 4;
testDeletedCounter.imei = 3;
testDeletedCounter.imsi = 1;
testDeletedCounter['security-coverage'] = 22;
testDeletedCounter['security-coverage-result'] = 19;

export const doTotal = (eventCounter: Record<string, number>) => {
  const allRecordKeys = Object.keys(eventCounter);
  let total = 0;
  for (let i = 0; i < allRecordKeys.length; i += 1) {
    total += eventCounter[allRecordKeys[i]];
  }
  return total;
};

export const RAW_EVENTS_SIZE = doTotal(testCreatedCounter) + doTotal(testMergedCounter) + doTotal(testDeletedCounter) + doTotal(testUpdatedCounter);
