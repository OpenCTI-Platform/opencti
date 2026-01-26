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
testCreatedCounter.artifact = 3;
testCreatedCounter['attack-pattern'] = 10;
testCreatedCounter.campaign = 6;
testCreatedCounter['case-incident'] = 7;
testCreatedCounter['case-rfi'] = 10;
testCreatedCounter['case-rft'] = 1;
testCreatedCounter.channel = 1;
testCreatedCounter['course-of-action'] = 4;
testCreatedCounter.credential = 1;
testCreatedCounter['data-component'] = 2;
testCreatedCounter['data-source'] = 2;
testCreatedCounter['email-addr'] = 1;
testCreatedCounter.event = 1;
testCreatedCounter['external-reference'] = 17;
testCreatedCounter.feedback = 2;
testCreatedCounter.file = 10;
testCreatedCounter.grouping = 2;
testCreatedCounter.identity = 47;
testCreatedCounter.incident = 3;
testCreatedCounter.indicator = 47;
testCreatedCounter.infrastructure = 1;
testCreatedCounter['intrusion-set'] = 4;
testCreatedCounter['ipv4-addr'] = 1;
testCreatedCounter['kill-chain-phase'] = 3;
testCreatedCounter.label = 19;
testCreatedCounter.language = 1;
testCreatedCounter.location = 24;
testCreatedCounter.malware = 51;
testCreatedCounter['malware-analysis'] = 3;
testCreatedCounter['marking-definition'] = 22;
testCreatedCounter.narrative = 1;
testCreatedCounter['network-traffic'] = 1;
testCreatedCounter.note = 4;
testCreatedCounter['observed-data'] = 1;
testCreatedCounter.opinion = 5;
testCreatedCounter.persona = 1;
testCreatedCounter['ssh-key'] = 1;
testCreatedCounter.relationship = 133;
testCreatedCounter.report = 36;
testCreatedCounter.sighting = 4;
testCreatedCounter.software = 1;
testCreatedCounter['threat-actor'] = 21;
testCreatedCounter.tool = 5;
testCreatedCounter['tracking-number'] = 1;
testCreatedCounter.vocabulary = VOCABULARY_NUMBERS;
testCreatedCounter.vulnerability = 8;

export const testUpdatedCounter: Record<string, number> = {};
testUpdatedCounter['marking-definition'] = 2;
testUpdatedCounter.relationship = 8;
testUpdatedCounter.campaign = 7;
testUpdatedCounter.identity = 25;
testUpdatedCounter.malware = 20;
testUpdatedCounter.file = 19;
testUpdatedCounter['intrusion-set'] = 4;
testUpdatedCounter['data-component'] = 7;
testUpdatedCounter.location = 15;
testUpdatedCounter['attack-pattern'] = 3;
testUpdatedCounter['case-incident'] = 11;
testUpdatedCounter.feedback = 1;
testUpdatedCounter.report = 12;
testUpdatedCounter['course-of-action'] = 3;
testUpdatedCounter['data-source'] = 1;
testUpdatedCounter['external-reference'] = 1;
testUpdatedCounter.grouping = 3;
testUpdatedCounter.incident = 3;
testUpdatedCounter.indicator = 23;
testUpdatedCounter.label = 1;
testUpdatedCounter['malware-analysis'] = 3;
testUpdatedCounter.note = 3;
testUpdatedCounter.opinion = 6;
testUpdatedCounter['email-addr'] = 1;
testUpdatedCounter.persona = 1;
testUpdatedCounter['ssh-key'] = 1;
testUpdatedCounter['case-rfi'] = 10;
testUpdatedCounter['ipv4-addr'] = 4;
testUpdatedCounter.tool = 10;
testUpdatedCounter.sighting = 4;
testUpdatedCounter['threat-actor'] = 18;
testUpdatedCounter.vocabulary = 3;
testUpdatedCounter.vulnerability = 3;

export const testMergedCounter: Record<string, number> = {};
testMergedCounter['threat-actor'] = 1;
testMergedCounter.identity = 1;
testMergedCounter.report = 3;
testMergedCounter.file = 3;
testMergedCounter.artifact = 1;

export const testDeletedCounter: Record<string, number> = {};
testDeletedCounter.artifact = 2;
testDeletedCounter['attack-pattern'] = 5;
testDeletedCounter.campaign = 2;
testDeletedCounter['case-incident'] = 7;
testDeletedCounter['case-rfi'] = 10;
testDeletedCounter['case-rft'] = 1;
testDeletedCounter.channel = 1;
testDeletedCounter['course-of-action'] = 2;
testDeletedCounter['data-component'] = 2;
testDeletedCounter['data-source'] = 2;
testDeletedCounter['email-addr'] = 1;
testDeletedCounter.event = 1;
testDeletedCounter['external-reference'] = 1;
testDeletedCounter.feedback = 2;
testDeletedCounter.file = 6;
testDeletedCounter.grouping = 2;
testDeletedCounter.identity = 31;
testDeletedCounter.incident = 2;
testDeletedCounter.indicator = 19;
testDeletedCounter.infrastructure = 1;
testDeletedCounter['intrusion-set'] = 3;
testDeletedCounter['ipv4-addr'] = 1;
testDeletedCounter.label = 2;
testDeletedCounter.language = 1;
testDeletedCounter.location = 16;
testDeletedCounter.malware = 24;
testDeletedCounter['malware-analysis'] = 2;
testDeletedCounter['marking-definition'] = 11;
testDeletedCounter.narrative = 1;
testDeletedCounter['network-traffic'] = 1;
testDeletedCounter.note = 3;
testDeletedCounter.opinion = 4;
testDeletedCounter.persona = 1;
testDeletedCounter.relationship = 1;
testDeletedCounter.report = 28;
testDeletedCounter.sighting = 1;
testDeletedCounter['ssh-key'] = 1;
testDeletedCounter['threat-actor'] = 12;
testDeletedCounter.tool = 5;
testDeletedCounter.vulnerability = 2;

export const doTotal = (eventCounter: Record<string, number>) => {
  const allRecordKeys = Object.keys(eventCounter);
  let total = 0;
  for (let i = 0; i < allRecordKeys.length; i += 1) {
    total += eventCounter[allRecordKeys[i]];
  }
  return total;
};

export const RAW_EVENTS_SIZE = doTotal(testCreatedCounter) + doTotal(testMergedCounter) + doTotal(testDeletedCounter) + doTotal(testUpdatedCounter);
