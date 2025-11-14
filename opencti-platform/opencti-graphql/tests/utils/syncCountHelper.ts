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
import { VOCABULARY_NUMBERS } from '../04-sync/sync-utils';

export const testCreatedCounter: Record<string, number> = {};
testCreatedCounter.artifact = 3;
testCreatedCounter['attack-pattern'] = 9;
testCreatedCounter.campaign = 5;
testCreatedCounter['case-incident'] = 6;
testCreatedCounter['case-rfi'] = 9;
testCreatedCounter['course-of-action'] = 3;
testCreatedCounter.credential = 1;
testCreatedCounter['data-component'] = 5;
testCreatedCounter['data-source'] = 1;
testCreatedCounter['email-addr'] = 1;
testCreatedCounter['external-reference'] = 17;
testCreatedCounter.feedback = 1;
testCreatedCounter.file = 10;
testCreatedCounter.grouping = 1;
testCreatedCounter.identity = 40;
testCreatedCounter.incident = 2;
testCreatedCounter.indicator = 46;
testCreatedCounter['intrusion-set'] = 3;
testCreatedCounter['ipv4-addr'] = 1;
testCreatedCounter['kill-chain-phase'] = 3;
testCreatedCounter.label = 19;
testCreatedCounter.location = 19;
testCreatedCounter.malware = 49;
testCreatedCounter['malware-analysis'] = 2;
testCreatedCounter['marking-definition'] = 21;
testCreatedCounter['network-traffic'] = 1;
testCreatedCounter.note = 3;
testCreatedCounter['observed-data'] = 1;
testCreatedCounter.opinion = 4;
testCreatedCounter.persona = 1;
testCreatedCounter['ssh-key'] = 1;
testCreatedCounter.relationship = 133;
testCreatedCounter.report = 34;
testCreatedCounter.sighting = 4;
testCreatedCounter.software = 1;
testCreatedCounter['threat-actor'] = 17;
testCreatedCounter.tool = 2;
testCreatedCounter['tracking-number'] = 1;
testCreatedCounter.vocabulary = VOCABULARY_NUMBERS;
testCreatedCounter.vulnerability = 7;

export const testUpdatedCounter: Record<string, number> = {};
testUpdatedCounter['marking-definition'] = 2;
testUpdatedCounter.relationship = 8;
testUpdatedCounter.campaign = 7;
testUpdatedCounter.identity = 25;
testUpdatedCounter.malware = 20;
testUpdatedCounter.file = 19;
testUpdatedCounter['intrusion-set'] = 4;
testUpdatedCounter['data-component'] = 4;
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
testUpdatedCounter.tool = 9;
testUpdatedCounter.sighting = 4;
testUpdatedCounter['threat-actor'] = 17;
testUpdatedCounter.vocabulary = 3;
testUpdatedCounter.vulnerability = 3;

export const testMergedCounter: Record<string, number> = {};
testMergedCounter['threat-actor'] = 1;
testMergedCounter.identity = 1;
testMergedCounter.report = 3;
testMergedCounter.file = 3;
testMergedCounter.artifact = 1;

export const testDeletedCounter: Record<string, number> = {};
testDeletedCounter.report = 26;
testDeletedCounter['marking-definition'] = 10;
testDeletedCounter['threat-actor'] = 8;
testDeletedCounter['case-rfi'] = 9;
testDeletedCounter['attack-pattern'] = 4;
testDeletedCounter.malware = 22;
testDeletedCounter.identity = 24;
testDeletedCounter.file = 6;
testDeletedCounter['intrusion-set'] = 2;
testDeletedCounter.indicator = 18;
testDeletedCounter.label = 2;
testDeletedCounter['data-component'] = 5;
testDeletedCounter.artifact = 2;
testDeletedCounter.location = 11;
testDeletedCounter.campaign = 1;
testDeletedCounter['case-incident'] = 6;
testDeletedCounter.feedback = 1;
testDeletedCounter['course-of-action'] = 1;
testDeletedCounter['data-source'] = 1;
testDeletedCounter['external-reference'] = 1;
testDeletedCounter.grouping = 1;
testDeletedCounter.incident = 1;
testDeletedCounter['malware-analysis'] = 1;
testDeletedCounter.note = 2;
testDeletedCounter.opinion = 3;
testDeletedCounter['email-addr'] = 1;
testDeletedCounter.persona = 1;
testDeletedCounter.relationship = 1;
testDeletedCounter['ipv4-addr'] = 1;
testDeletedCounter['network-traffic'] = 1;
testDeletedCounter.tool = 2;
testDeletedCounter.sighting = 1;
testDeletedCounter.vulnerability = 1;
testDeletedCounter['ssh-key'] = 1;

export const doTotal = (eventCounter: Record<string, number>) => {
  const allRecordKeys = Object.keys(eventCounter);
  let total = 0;
  for (let i = 0; i < allRecordKeys.length; i += 1) {
    total += eventCounter[allRecordKeys[i]];
  }
  return total;
};

export const RAW_EVENTS_SIZE = doTotal(testCreatedCounter) + doTotal(testMergedCounter) + doTotal(testDeletedCounter) + doTotal(testUpdatedCounter);
