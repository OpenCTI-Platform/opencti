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
testCreatedCounter['attack-pattern'] = 28; // 3 created by timeline-test
testCreatedCounter.campaign = 6;
testCreatedCounter['case-incident'] = 27; // 9 created by timeline-test
testCreatedCounter['case-rfi'] = 14; // 5 created by timeline-test
testCreatedCounter['case-rft'] = 1;
testCreatedCounter.channel = 1;
testCreatedCounter['course-of-action'] = 4;
testCreatedCounter.credential = 1;
testCreatedCounter['data-component'] = 2;
testCreatedCounter['data-source'] = 2;
testCreatedCounter.directory = 3; // created and deleted by stixRefRelationships-test
testCreatedCounter['email-addr'] = 1;
testCreatedCounter.event = 2;
testCreatedCounter['external-reference'] = 19; // 2 created by timeline-test
testCreatedCounter.feedback = 2;
testCreatedCounter.file = 11;
testCreatedCounter.grouping = 2;
testCreatedCounter.iccid = 4;
testCreatedCounter.identity = 58;
testCreatedCounter.imei = 3;
testCreatedCounter.imsi = 1;
testCreatedCounter.incident = 8; // 1 created by timeline-test
testCreatedCounter.indicator = 58;
testCreatedCounter.infrastructure = 1;
// Counts for:
// - 2 created and deleted by enrichment-liveness-test
testCreatedCounter['intrusion-set'] = 8;
testCreatedCounter['ipv4-addr'] = 1;
testCreatedCounter['kill-chain-phase'] = 4;
testCreatedCounter.label = 17; // 2 created by timeline-test
testCreatedCounter.language = 1;
testCreatedCounter.location = 22;
testCreatedCounter['mac-addr'] = 1;
testCreatedCounter.malware = 70; // 5 created by timeline-test
testCreatedCounter['malware-analysis'] = 3;
testCreatedCounter['marking-definition'] = 24;
testCreatedCounter.narrative = 1;
testCreatedCounter['network-traffic'] = 1;
testCreatedCounter.note = 8; // 1 created by timeline-test
// 1 in the dataset + 2 created by observedData-domain-test
testCreatedCounter['observed-data'] = 3;
testCreatedCounter.opinion = 6; // 1 created by timeline-test
testCreatedCounter.persona = 1;
testCreatedCounter['phone-number'] = 2;
testCreatedCounter['ssh-key'] = 1;
testCreatedCounter.relationship = 150; // 3 created by timeline-test
testCreatedCounter.report = 59;
testCreatedCounter.sighting = 7;
testCreatedCounter.software = 2;
testCreatedCounter.task = 4; // 2 created by timeline-test
testCreatedCounter['threat-actor'] = 33;
testCreatedCounter.tool = 5;
testCreatedCounter['tracking-number'] = 1;
testCreatedCounter.vocabulary = VOCABULARY_NUMBERS;
testCreatedCounter.vulnerability = 11;
// Counts for:
// - 2 created and deleted by enrichment-liveness-test
testCreatedCounter['security-coverage'] = 27;
testCreatedCounter['security-coverage-result'] = 22;

export const testUpdatedCounter: Record<string, number> = {};
testUpdatedCounter['marking-definition'] = 2;
testUpdatedCounter.relationship = 9;
testUpdatedCounter.campaign = 7;
testUpdatedCounter.identity = 33;
testUpdatedCounter.malware = 23; // 1 marking added by timeline-test
testUpdatedCounter.file = 27;
testUpdatedCounter['intrusion-set'] = 5;
testUpdatedCounter['data-component'] = 7;
testUpdatedCounter.location = 14;
testUpdatedCounter['attack-pattern'] = 3;
testUpdatedCounter['case-incident'] = 18;
testUpdatedCounter.feedback = 1;
testUpdatedCounter.report = 28;
testUpdatedCounter['course-of-action'] = 3;
testUpdatedCounter['data-source'] = 1;
testUpdatedCounter['external-reference'] = 1;
testUpdatedCounter.grouping = 3;
testUpdatedCounter.incident = 5; // 1 status change by timeline-test
testUpdatedCounter.indicator = 30;
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
testUpdatedCounter.sighting = 5;
testUpdatedCounter['threat-actor'] = 18;
testUpdatedCounter.vocabulary = 3;
testUpdatedCounter.vulnerability = 5;
testUpdatedCounter.iccid = 1;
testUpdatedCounter.imei = 1;
testUpdatedCounter.imsi = 1;
testUpdatedCounter['security-coverage'] = 1;
testUpdatedCounter['security-coverage-result'] = 4;
testUpdatedCounter.task = 2; // 2 status changes by timeline-test

export const testMergedCounter: Record<string, number> = {};
testMergedCounter['threat-actor'] = 5;
testMergedCounter.identity = 1;
testMergedCounter.report = 3;
testMergedCounter.file = 3;
testMergedCounter.artifact = 1;
testMergedCounter['attack-pattern'] = 1;
testMergedCounter['case-incident'] = 1;

export const testDeletedCounter: Record<string, number> = {};
testDeletedCounter.artifact = 3;
testDeletedCounter['attack-pattern'] = 23; // 3 created and deleted by timeline-test
testDeletedCounter.campaign = 2;
testDeletedCounter['case-incident'] = 25; // 9 created and deleted by timeline-test
testDeletedCounter['case-rfi'] = 14; // 5 created and deleted by timeline-test
testDeletedCounter['case-rft'] = 1;
testDeletedCounter.channel = 1;
testDeletedCounter['course-of-action'] = 2;
testDeletedCounter['data-component'] = 2;
testDeletedCounter['data-source'] = 2;
testDeletedCounter.directory = 3; // created and deleted by stixRefRelationships-test
testDeletedCounter['email-addr'] = 1;
testDeletedCounter.event = 2;
testDeletedCounter['external-reference'] = 3; // 2 created and deleted by timeline-test
testDeletedCounter.feedback = 2;
testDeletedCounter.file = 7;
testDeletedCounter.grouping = 2;
testDeletedCounter.identity = 41;
testDeletedCounter.incident = 7; // 1 created and deleted by timeline-test
testDeletedCounter.indicator = 30;
testDeletedCounter.infrastructure = 1;
// Counts for:
// - 2 created and deleted by enrichment-liveness-test
testDeletedCounter['intrusion-set'] = 7;
testDeletedCounter['ipv4-addr'] = 1;
testDeletedCounter['kill-chain-phase'] = 1; // created and deleted by timeline-test
testDeletedCounter.label = 4; // 2 created and deleted by timeline-test
testDeletedCounter.language = 1;
testDeletedCounter.location = 17;
testDeletedCounter['mac-addr'] = 1;
testDeletedCounter.malware = 43; // 5 created and deleted by timeline-test
testDeletedCounter['malware-analysis'] = 2;
testDeletedCounter['marking-definition'] = 13;
testDeletedCounter.narrative = 1;
testDeletedCounter['network-traffic'] = 1;
testDeletedCounter.note = 7; // 1 created and deleted by timeline-test
testDeletedCounter['observed-data'] = 2; // created and deleted by observedData-domain-test
testDeletedCounter.opinion = 5; // 1 created and deleted by timeline-test
testDeletedCounter.persona = 1;
testDeletedCounter['phone-number'] = 2;
testDeletedCounter.relationship = 8; // 3 created and deleted by timeline-test
testDeletedCounter.report = 50;
testDeletedCounter.sighting = 4; // 2 created and deleted by timeline-test
testDeletedCounter['ssh-key'] = 1;
testDeletedCounter.task = 4; // 2 created and deleted by timeline-test
testDeletedCounter['threat-actor'] = 20;
testDeletedCounter.tool = 5;
testDeletedCounter.vulnerability = 5;
testDeletedCounter.software = 1;
testDeletedCounter.iccid = 4;
testDeletedCounter.imei = 3;
testDeletedCounter.imsi = 1;
// Counts for:
// - 2 created and deleted by enrichment-liveness-test
testDeletedCounter['security-coverage'] = 25;
testDeletedCounter['security-coverage-result'] = 20;

export const doTotal = (eventCounter: Record<string, number>) => {
  const allRecordKeys = Object.keys(eventCounter);
  let total = 0;
  for (let i = 0; i < allRecordKeys.length; i += 1) {
    total += eventCounter[allRecordKeys[i]];
  }
  return total;
};

export const RAW_EVENTS_SIZE = doTotal(testCreatedCounter) + doTotal(testMergedCounter) + doTotal(testDeletedCounter) + doTotal(testUpdatedCounter);
