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
// Includes 1 created and deleted by the has-covered cleanup tests of securityCoverage-utils-test
testCreatedCounter.artifact = 5;
// 2 created by ingestionDeduplication-test (an import, then the same import after the deletion), +1 sub-technique created and deleted by attackPattern-test (x_mitre_id)
// 2 created and deleted by killChainPhase-merge-test
// +2 created and deleted by middleware-test (renames keeping aliases)
// Includes 23 created and deleted by the has-covered cleanup tests of securityCoverage-utils-test
// 6 created and deleted by securityCoverage-results-filters-test (5) and vocabulary-coverage-usages-test (1) (tested entities)
testCreatedCounter['attack-pattern'] = 61;
// 2 created and deleted by upsert-limit-dates-test
// Includes 1 created and deleted by the has-covered cleanup tests of securityCoverage-utils-test
testCreatedCounter.campaign = 9;
// 3 created by workflow-closing-reason-test merge and external status write cases
testCreatedCounter['case-incident'] = 23;
// 40 case-rfi and 1 case-rft created by the request access workflow tests (requestAccess-test, requestAccess-domain-test, workflow-test)
testCreatedCounter['case-rfi'] = 49;
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
// Includes 1 created and deleted by the has-covered cleanup tests of securityCoverage-utils-test (author of a created-by test)
testCreatedCounter.identity = 64;
testCreatedCounter.imei = 3;
testCreatedCounter.imsi = 1;
testCreatedCounter.incident = 9; // 2 created and deleted by upsert-limit-dates-test
// Includes 1 created and deleted by markingDefinition-test (OASIS TLP 2.0 RED id)
testCreatedCounter.indicator = 65;
testCreatedCounter.infrastructure = 1;
// Counts for:
// - 2 created and deleted by enrichment-liveness-test
// - 1 created and deleted by stixRelationship-test (time series breakdown)
// - 2 created and deleted by upsert-limit-dates-test
// - 4 created and deleted by the has-covered cleanup tests of securityCoverage-utils-test
testCreatedCounter['intrusion-set'] = 61;
// 1 created and deleted by stixCyberObservable-test (network traffic deduplication)
testCreatedCounter['ipv4-addr'] = 2;
// Counts for:
// - 1 created and deleted by form-submission-test
// - 3 created and deleted by killChainPhase-import-test
// - 3 created by the data files the tests load (kill_chain_phases of their objects), never deleted
// - 2 created by killChainPhase-merge-test (1 merged into the other, which is then deleted)
testCreatedCounter['kill-chain-phase'] = 9;
// Counts for:
// - 3 created and deleted by investigation-enrichment-test
// - 3 created and deleted by label-import-test
// - 3 created and deleted by stixCoreObject-test (time series breakdown)
testCreatedCounter.label = 24;
testCreatedCounter.language = 1;
testCreatedCounter.location = 23; // includes 1 created and deleted by publicDashboard-test (time series breakdown)
testCreatedCounter['mac-addr'] = 1;
// Includes 2 created and deleted by form-submission-test (a verified form import, an existing one left as it is),
// 2 by stixRelationship-test and 1 by publicDashboard-test (time series breakdown), and 5 by ingestionDeduplication-domain-test,
// and 2 by upsert-limit-dates-test
testCreatedCounter.malware = 79; // and 2 by the request access workflow tests
testCreatedCounter['malware-analysis'] = 3;
testCreatedCounter['marking-definition'] = 29;
testCreatedCounter.narrative = 1;
// 1 created and deleted by stixCyberObservable-test (network traffic deduplication)
testCreatedCounter['network-traffic'] = 2;
testCreatedCounter.note = 7;
// 1 in the dataset + 2 created by observedData-domain-test
testCreatedCounter['observed-data'] = 3;
testCreatedCounter.opinion = 5;
testCreatedCounter.persona = 1;
testCreatedCounter['phone-number'] = 2;
testCreatedCounter['ssh-key'] = 1;
// Includes 5 created and deleted by stixRelationship-test, and 1 created by publicDashboard-test, deleted with its target (time series breakdown)
// Includes 40 created by the has-covered cleanup tests of securityCoverage-utils-test (uses, targets and has-covered), 13 of them deleted
// 6 has-covered created by securityCoverage-results-filters-test (5) and vocabulary-coverage-usages-test (1), deleted with their targets
testCreatedCounter.relationship = 201; // +1 subtechnique-of created by attackPattern-test, removed with its sub-technique
// Includes 8 created and deleted by stixCoreObject-test and 5 by publicDashboard-test (time series breakdown), and 1 by audit-test (audits breakdown)
// Plus 3 created and deleted by workflow-entity-write-test
// Includes 5 created and deleted by the has-covered cleanup tests of securityCoverage-utils-test
// 2 by securityCoverage-results-filters-test and vocabulary-coverage-usages-test
testCreatedCounter.report = 84;
testCreatedCounter.sighting = 8; // 3 created and deleted by relations-deduplication-test
// 1 created and deleted by stixCyberObservable-test (software purl)
testCreatedCounter.software = 3;
testCreatedCounter.task = 1;
testCreatedCounter['threat-actor'] = 36; // 3 created and deleted by upsert-limit-dates-test
testCreatedCounter.tool = 5;
testCreatedCounter['tracking-number'] = 1;
// Counts for:
// - 3 created and deleted by vocabulary-import-test
testCreatedCounter.vocabulary = VOCABULARY_NUMBERS + 3;
// 1 created and deleted by ingestionDeduplication-test (a type outside the deduplication allowlist)
// 3 created and deleted by filterGroup-test (nil / not_nil operators on numbers)
// Includes 6 created and deleted by the has-covered cleanup tests of securityCoverage-utils-test
testCreatedCounter.vulnerability = 21;
// Counts for:
// - 2 created and deleted by enrichment-liveness-test
// - 10 created and deleted by the has-covered cleanup tests of securityCoverage-utils-test
// - 2 created and deleted by securityCoverage-results-filters-test and vocabulary-coverage-usages-test, with 3 results (2 + 1)
testCreatedCounter['security-coverage'] = 39;
// Includes 10 created and deleted by the has-covered cleanup tests of securityCoverage-utils-test
testCreatedCounter['security-coverage-result'] = 35;

export const testUpdatedCounter: Record<string, number> = {};
// Counts for:
// - 2 by configPreset-import-markings-test (a built-in marking changed then imported back)
testUpdatedCounter['marking-definition'] = 5;
testUpdatedCounter.relationship = 9;
testUpdatedCounter.campaign = 7;
// 5 by user-test: an organization administrator added then removed by the deletion of the user (2),
// two administrators added then removed concurrently (3)
testUpdatedCounter.identity = 38;
// 1 by ingestionDeduplication-domain-test (an edit in the platform), 1 by upsert-limit-dates-test (real dates upserted)
testUpdatedCounter.malware = 25; // and 1 org sharing by the request access workflow tests
testUpdatedCounter.file = 27;
testUpdatedCounter['intrusion-set'] = 18;
testUpdatedCounter['data-component'] = 7;
testUpdatedCounter.location = 14;
// 3 by ingestionDeduplication-test (a change at the source, an edit in the platform, the source content applied again)
// +4 by middleware-test (renames keeping aliases)
// Includes 1 by the has-covered cleanup tests of securityCoverage-utils-test (created-by added)
testUpdatedCounter['attack-pattern'] = 11;
// 5 by workflow-closing-reason-test merge (1) and external status write (4) cases
testUpdatedCounter['case-incident'] = 28;
testUpdatedCounter.feedback = 1;
// Includes 3 by the has-covered cleanup tests of securityCoverage-utils-test (objects removed)
testUpdatedCounter.report = 36; // includes 2 by audit-test (audits breakdown), and 1 status written by a transition in workflow-entity-write-test
testUpdatedCounter['course-of-action'] = 3;
testUpdatedCounter['data-source'] = 1;
testUpdatedCounter['external-reference'] = 1;
testUpdatedCounter.grouping = 3;
testUpdatedCounter.incident = 5; // 1 by upsert-limit-dates-test (severity upserted, dates kept)
testUpdatedCounter.indicator = 35;
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
// 43 case-rfi and 2 case-rft updated by the request access workflow tests (status transitions, decisions)
testUpdatedCounter['case-rfi'] = 48;
testUpdatedCounter['case-rft'] = 2;
// 1 updated by stixCyberObservable-test (network traffic deduplication)
testUpdatedCounter['ipv4-addr'] = 5;
// 3 updated by stixCyberObservable-test (2 upserts and 1 contributing field update in network traffic deduplication)
testUpdatedCounter['network-traffic'] = 3;
testUpdatedCounter.tool = 10;
// 1 updated by stixCyberObservable-test (software purl upsert with another purl)
testUpdatedCounter.software = 1;
testUpdatedCounter.sighting = 7; // 2 upserts in relations-deduplication-test
testUpdatedCounter['threat-actor'] = 19; // 1 by upsert-limit-dates-test (synchronized upsert)
// Counts for:
// - 2 updated by vocabulary-import-test (the description of an entry of the platform, edited then restored)
// - 32 updated by vocabulary-test parent entry behavior: HOST renamed and restored (2 + 2 x 7 subcategories parent_name),
//   SERVER description edited and restored (2), CONTAINER_WORKLOAD renamed and restored (2 + 2 x 6 subcategories parent_name)
testUpdatedCounter.vocabulary = 3 + 2 + 32;
testUpdatedCounter.vulnerability = 5;
testUpdatedCounter.iccid = 1;
testUpdatedCounter.imei = 1;
testUpdatedCounter.imsi = 1;
// Includes 3 by the has-covered cleanup tests of securityCoverage-utils-test (covered report updated)
testUpdatedCounter['security-coverage'] = 4;
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
testMergedCounter['kill-chain-phase'] = 1; // killChainPhase-merge-test

export const testDeletedCounter: Record<string, number> = {};
// Includes 1 by the has-covered cleanup tests of securityCoverage-utils-test
testDeletedCounter.artifact = 4;
// 2 by ingestionDeduplication-test, +1 sub-technique deleted by attackPattern-test (x_mitre_id), +2 by killChainPhase-merge-test
// +2 by middleware-test (renames keeping aliases)
// Includes 23 by the has-covered cleanup tests of securityCoverage-utils-test
// 6 by securityCoverage-results-filters-test (5) and vocabulary-coverage-usages-test (1)
testDeletedCounter['attack-pattern'] = 56;
// Includes 1 by the has-covered cleanup tests of securityCoverage-utils-test
testDeletedCounter.campaign = 5; // 2 by upsert-limit-dates-test
// 2 by workflow-closing-reason-test merge and external status write cases, the merged source has no delete event
testDeletedCounter['case-incident'] = 20;
// 39 case-rfi and 1 case-rft deleted by the request access workflow tests (1 more case-rfi is merged)
testDeletedCounter['case-rfi'] = 48;
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
// Includes 1 by the has-covered cleanup tests of securityCoverage-utils-test
testDeletedCounter.identity = 47;
testDeletedCounter.incident = 8; // 2 by upsert-limit-dates-test
// Includes 1 created and deleted by markingDefinition-test (OASIS TLP 2.0 RED id)
testDeletedCounter.indicator = 37;
testDeletedCounter.infrastructure = 1;
// Counts for:
// - 2 created and deleted by enrichment-liveness-test
// - 1 created and deleted by stixRelationship-test (time series breakdown)
// - 2 created and deleted by upsert-limit-dates-test
// - 4 by the has-covered cleanup tests of securityCoverage-utils-test
testDeletedCounter['intrusion-set'] = 59;
// 1 created and deleted by stixCyberObservable-test (network traffic deduplication)
testDeletedCounter['ipv4-addr'] = 2;
// Counts for:
// - 1 created and deleted by form-submission-test
// - 3 deleted by killChainPhase-import-test
// - 1 deleted by killChainPhase-merge-test (the merge target; the merged source has no delete event)
testDeletedCounter['kill-chain-phase'] = 5;
// Counts for:
// - 3 created and deleted by investigation-enrichment-test
// - 3 deleted by label-import-test
// - 3 created and deleted by stixCoreObject-test (time series breakdown)
testDeletedCounter.label = 11;
testDeletedCounter.language = 1;
testDeletedCounter.location = 18; // includes 1 created and deleted by publicDashboard-test (time series breakdown)
testDeletedCounter['mac-addr'] = 1;
// Includes 2 created and deleted by form-submission-test, and 2 by stixRelationship-test and 1 by publicDashboard-test (time series breakdown),
// and 5 by ingestionDeduplication-domain-test, and 2 by upsert-limit-dates-test
testDeletedCounter.malware = 52; // and 2 by the request access workflow tests
testDeletedCounter['malware-analysis'] = 2;
testDeletedCounter['marking-definition'] = 18;
testDeletedCounter.narrative = 1;
// 1 created and deleted by stixCyberObservable-test (network traffic deduplication)
testDeletedCounter['network-traffic'] = 2;
testDeletedCounter.note = 6;
testDeletedCounter['observed-data'] = 2; // created and deleted by observedData-domain-test
testDeletedCounter.opinion = 4;
testDeletedCounter.persona = 1;
testDeletedCounter['phone-number'] = 2;
// Includes 13 by the has-covered cleanup tests of securityCoverage-utils-test (8 has-covered cleaned up, 5 uses or targets removed)
testDeletedCounter.relationship = 23; // includes 5 created and deleted by stixRelationship-test (time series breakdown)
// Includes 8 created and deleted by stixCoreObject-test and 5 by publicDashboard-test (time series breakdown), and 1 by audit-test (audits breakdown)
// Plus 3 created and deleted by workflow-entity-write-test
// Includes 5 by the has-covered cleanup tests of securityCoverage-utils-test
// 2 by securityCoverage-results-filters-test and vocabulary-coverage-usages-test
testDeletedCounter.report = 75;
testDeletedCounter.sighting = 5; // 3 created and deleted by relations-deduplication-test
testDeletedCounter['ssh-key'] = 1;
testDeletedCounter.task = 1;
testDeletedCounter['threat-actor'] = 23; // 3 by upsert-limit-dates-test
testDeletedCounter.tool = 5;
// Counts for:
// - 3 deleted by vocabulary-import-test
testDeletedCounter.vocabulary = 3;
// 1 by ingestionDeduplication-test
// 3 by filterGroup-test (nil / not_nil operators on numbers)
// Includes 6 by the has-covered cleanup tests of securityCoverage-utils-test
testDeletedCounter.vulnerability = 15;
// 1 created and deleted by stixCyberObservable-test (software purl)
testDeletedCounter.software = 2;
testDeletedCounter.iccid = 4;
testDeletedCounter.imei = 3;
testDeletedCounter.imsi = 1;
// Counts for:
// - 2 created and deleted by enrichment-liveness-test
// - 10 by the has-covered cleanup tests of securityCoverage-utils-test
// - 2 by securityCoverage-results-filters-test and vocabulary-coverage-usages-test, with 3 results (2 + 1)
testDeletedCounter['security-coverage'] = 37;
// Includes 10 by the has-covered cleanup tests of securityCoverage-utils-test
testDeletedCounter['security-coverage-result'] = 33;

export const doTotal = (eventCounter: Record<string, number>) => {
  const allRecordKeys = Object.keys(eventCounter);
  let total = 0;
  for (let i = 0; i < allRecordKeys.length; i += 1) {
    total += eventCounter[allRecordKeys[i]];
  }
  return total;
};

export const RAW_EVENTS_SIZE = doTotal(testCreatedCounter) + doTotal(testMergedCounter) + doTotal(testDeletedCounter) + doTotal(testUpdatedCounter);
