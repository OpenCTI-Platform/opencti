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
// 2 created by ingestionDeduplication-test (an import, then the same import after the deletion)
testCreatedCounter['attack-pattern'] = 27;
testCreatedCounter.campaign = 6;
// 3 created by workflow-closing-reason-test merge and external status write cases
testCreatedCounter['case-incident'] = 23;
// 32 case-rfi and 1 case-rft created by the request access workflow tests (requestAccess-test, requestAccess-domain-test, workflow-test)
testCreatedCounter['case-rfi'] = 41;
testCreatedCounter['case-rft'] = 2;
testCreatedCounter.channel = 1;
testCreatedCounter['course-of-action'] = 4;
testCreatedCounter.credential = 1;
testCreatedCounter['data-component'] = 2;
testCreatedCounter['data-source'] = 2;
testCreatedCounter.directory = 3; // created and deleted by stixRefRelationships-test
testCreatedCounter['email-addr'] = 1;
testCreatedCounter.event = 2;
testCreatedCounter['external-reference'] = 17;
testCreatedCounter.feedback = 2;
testCreatedCounter.file = 11;
testCreatedCounter.grouping = 2;
testCreatedCounter.iccid = 4;
// Includes 1 created and deleted by stixCoreObject-test, 1 by stixRelationship-test and 1 by publicDashboard-test (time series breakdown),
// and 2 by ingestionDeduplication-domain-test (authors of imported malware)
testCreatedCounter.identity = 63;
testCreatedCounter.imei = 3;
testCreatedCounter.imsi = 1;
testCreatedCounter.incident = 7;
testCreatedCounter.indicator = 61;
testCreatedCounter.infrastructure = 1;
// Counts for:
// - 2 created and deleted by enrichment-liveness-test
// - 1 created and deleted by stixRelationship-test (time series breakdown)
testCreatedCounter['intrusion-set'] = 55;
testCreatedCounter['ipv4-addr'] = 1;
// Counts for:
// - 1 created and deleted by form-submission-test
// - 3 created and deleted by killChainPhase-import-test
// - 3 created by the data files the tests load (kill_chain_phases of their objects), never deleted
testCreatedCounter['kill-chain-phase'] = 7;
// Counts for:
// - 3 created and deleted by investigation-enrichment-test
// - 3 created and deleted by label-import-test
// - 3 created and deleted by stixCoreObject-test (time series breakdown)
testCreatedCounter.label = 24;
testCreatedCounter.language = 1;
testCreatedCounter.location = 23; // includes 1 created and deleted by publicDashboard-test (time series breakdown)
testCreatedCounter['mac-addr'] = 1;
// Includes 2 created and deleted by form-submission-test (a verified form import, an existing one left as it is),
// 2 by stixRelationship-test and 1 by publicDashboard-test (time series breakdown), and 5 by ingestionDeduplication-domain-test
testCreatedCounter.malware = 77; // 2 by the request access workflow tests
testCreatedCounter['malware-analysis'] = 3;
testCreatedCounter['marking-definition'] = 29;
testCreatedCounter.narrative = 1;
testCreatedCounter['network-traffic'] = 1;
testCreatedCounter.note = 7;
// 1 in the dataset + 2 created by observedData-domain-test
testCreatedCounter['observed-data'] = 3;
testCreatedCounter.opinion = 5;
testCreatedCounter.persona = 1;
testCreatedCounter['phone-number'] = 2;
testCreatedCounter['ssh-key'] = 1;
// Includes 5 created and deleted by stixRelationship-test, and 1 created by publicDashboard-test, deleted with its target (time series breakdown)
testCreatedCounter.relationship = 154;
// Includes 8 created and deleted by stixCoreObject-test and 5 by publicDashboard-test (time series breakdown), and 1 by audit-test (audits breakdown)
// Plus 3 created and deleted by workflow-entity-write-test
testCreatedCounter.report = 77;
testCreatedCounter.sighting = 8; // 3 created and deleted by relations-deduplication-test
testCreatedCounter.software = 2;
testCreatedCounter.task = 1;
testCreatedCounter['threat-actor'] = 33;
testCreatedCounter.tool = 5;
testCreatedCounter['tracking-number'] = 1;
// Counts for:
// - 3 created and deleted by vocabulary-import-test
testCreatedCounter.vocabulary = VOCABULARY_NUMBERS + 3;
// 1 created and deleted by ingestionDeduplication-test (a type outside the deduplication allowlist)
testCreatedCounter.vulnerability = 12;
// Counts for:
// - 2 created and deleted by enrichment-liveness-test
testCreatedCounter['security-coverage'] = 27;
testCreatedCounter['security-coverage-result'] = 22;

export const testUpdatedCounter: Record<string, number> = {};
testUpdatedCounter['marking-definition'] = 3;
testUpdatedCounter.relationship = 9;
testUpdatedCounter.campaign = 7;
testUpdatedCounter.identity = 33;
// 1 by ingestionDeduplication-domain-test (an edit in the platform)
testUpdatedCounter.malware = 24; // 1 org sharing by the request access workflow tests
testUpdatedCounter.file = 27;
testUpdatedCounter['intrusion-set'] = 18;
testUpdatedCounter['data-component'] = 7;
testUpdatedCounter.location = 14;
// 3 by ingestionDeduplication-test (a change at the source, an edit in the platform, the source content applied again)
testUpdatedCounter['attack-pattern'] = 6;
// 5 by workflow-closing-reason-test merge (1) and external status write (4) cases
testUpdatedCounter['case-incident'] = 28;
testUpdatedCounter.feedback = 1;
testUpdatedCounter.report = 33; // includes 2 by audit-test (audits breakdown), and 1 status written by a transition in workflow-entity-write-test
testUpdatedCounter['course-of-action'] = 3;
testUpdatedCounter['data-source'] = 1;
testUpdatedCounter['external-reference'] = 1;
testUpdatedCounter.grouping = 3;
testUpdatedCounter.incident = 4;
testUpdatedCounter.indicator = 33;
// Counts for:
// - 3 updated by killChainPhase-import-test
testUpdatedCounter['kill-chain-phase'] = 3;
// Counts for:
// - 1 updated by label-import-test
testUpdatedCounter.label = 2;
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
// 42 case-rfi and 2 case-rft updated by the request access workflow tests (status transitions, decisions)
testUpdatedCounter['case-rfi'] = 47;
testUpdatedCounter['case-rft'] = 2;
testUpdatedCounter['ipv4-addr'] = 4;
testUpdatedCounter.tool = 10;
testUpdatedCounter.sighting = 7; // 2 upserts in relations-deduplication-test
testUpdatedCounter['threat-actor'] = 18;
// Counts for:
// - 2 updated by vocabulary-import-test (the description of an entry of the platform, edited then restored)
testUpdatedCounter.vocabulary = 3 + 2;
testUpdatedCounter.vulnerability = 5;
testUpdatedCounter.iccid = 1;
testUpdatedCounter.imei = 1;
testUpdatedCounter.imsi = 1;
testUpdatedCounter['security-coverage'] = 1;
testUpdatedCounter['security-coverage-result'] = 4;

export const testMergedCounter: Record<string, number> = {};
testMergedCounter['threat-actor'] = 5;
testMergedCounter.identity = 1;
testMergedCounter.report = 3;
testMergedCounter.file = 3;
testMergedCounter.artifact = 1;
testMergedCounter['attack-pattern'] = 1;
testMergedCounter['case-incident'] = 2; // 1 by workflow-closing-reason-test merge case
testMergedCounter['intrusion-set'] = 1;
testMergedCounter['case-rfi'] = 1; // requestAccess-test merge of a decided RFI

export const testDeletedCounter: Record<string, number> = {};
testDeletedCounter.artifact = 3;
// 2 by ingestionDeduplication-test
testDeletedCounter['attack-pattern'] = 22;
testDeletedCounter.campaign = 2;
// 2 by workflow-closing-reason-test merge and external status write cases, the merged source has no delete event
testDeletedCounter['case-incident'] = 20;
// 31 case-rfi and 1 case-rft deleted by the request access workflow tests (1 more case-rfi is merged)
testDeletedCounter['case-rfi'] = 40;
testDeletedCounter['case-rft'] = 2;
testDeletedCounter.channel = 1;
testDeletedCounter['course-of-action'] = 2;
testDeletedCounter['data-component'] = 2;
testDeletedCounter['data-source'] = 2;
testDeletedCounter.directory = 3; // created and deleted by stixRefRelationships-test
testDeletedCounter['email-addr'] = 1;
testDeletedCounter.event = 2;
testDeletedCounter['external-reference'] = 1;
testDeletedCounter.feedback = 2;
testDeletedCounter.file = 7;
testDeletedCounter.grouping = 2;
// Includes 1 created and deleted by stixCoreObject-test, 1 by stixRelationship-test and 1 by publicDashboard-test (time series breakdown),
// and 2 by ingestionDeduplication-domain-test
testDeletedCounter.identity = 46;
testDeletedCounter.incident = 6;
testDeletedCounter.indicator = 33;
testDeletedCounter.infrastructure = 1;
// Counts for:
// - 2 created and deleted by enrichment-liveness-test
// - 1 created and deleted by stixRelationship-test (time series breakdown)
testDeletedCounter['intrusion-set'] = 53;
testDeletedCounter['ipv4-addr'] = 1;
// Counts for:
// - 1 created and deleted by form-submission-test
// - 3 deleted by killChainPhase-import-test
testDeletedCounter['kill-chain-phase'] = 4;
// Counts for:
// - 3 created and deleted by investigation-enrichment-test
// - 3 deleted by label-import-test
// - 3 created and deleted by stixCoreObject-test (time series breakdown)
testDeletedCounter.label = 11;
testDeletedCounter.language = 1;
testDeletedCounter.location = 18; // includes 1 created and deleted by publicDashboard-test (time series breakdown)
testDeletedCounter['mac-addr'] = 1;
// Includes 2 created and deleted by form-submission-test, and 2 by stixRelationship-test and 1 by publicDashboard-test (time series breakdown),
// and 5 by ingestionDeduplication-domain-test
testDeletedCounter.malware = 50; // 2 by the request access workflow tests
testDeletedCounter['malware-analysis'] = 2;
testDeletedCounter['marking-definition'] = 18;
testDeletedCounter.narrative = 1;
testDeletedCounter['network-traffic'] = 1;
testDeletedCounter.note = 6;
testDeletedCounter['observed-data'] = 2; // created and deleted by observedData-domain-test
testDeletedCounter.opinion = 4;
testDeletedCounter.persona = 1;
testDeletedCounter['phone-number'] = 2;
testDeletedCounter.relationship = 10; // includes 5 created and deleted by stixRelationship-test (time series breakdown)
// Includes 8 created and deleted by stixCoreObject-test and 5 by publicDashboard-test (time series breakdown), and 1 by audit-test (audits breakdown)
// Plus 3 created and deleted by workflow-entity-write-test
testDeletedCounter.report = 68;
testDeletedCounter.sighting = 5; // 3 created and deleted by relations-deduplication-test
testDeletedCounter['ssh-key'] = 1;
testDeletedCounter.task = 1;
testDeletedCounter['threat-actor'] = 20;
testDeletedCounter.tool = 5;
// Counts for:
// - 3 deleted by vocabulary-import-test
testDeletedCounter.vocabulary = 3;
// 1 by ingestionDeduplication-test
testDeletedCounter.vulnerability = 6;
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
