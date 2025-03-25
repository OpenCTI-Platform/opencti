import { describe, expect, it } from 'vitest';
import { restrictedStreamMessageForRelationship } from '../../../src/manager/publisherManager';

describe('Publisher manager behaviors test', async () => {
  it('should display restricted instead of the from/to of a relationship in a stream message', async () => {
    // no restrictions
    const streamMessage = '`admin` creates the relation located-at from `r1` (Report) to `London` (City)';
    const notificationMessage = '[relationship] r1 located-at London';
    expect(restrictedStreamMessageForRelationship(streamMessage, notificationMessage)).toEqual(streamMessage);
    // from and to are both restricted
    const streamMessageFromAndTo = '`admin` creates the relation exploits from `Paradise Ransomware` (Malware) to `CVE-2010-3333` (Vulnerability)';
    const notificationMessageFromAndTo = '[relationship] Restricted exploits Restricted';
    const resultMessageFromAndTo = '`admin` creates the relation exploits from `Restricted` to `Restricted`';
    expect(restrictedStreamMessageForRelationship(streamMessageFromAndTo, notificationMessageFromAndTo)).toEqual(resultMessageFromAndTo);
    // from is restricted
    const streamMessageFrom = '`admin` deletes the relation exploits from `Paradise Ransomware` (Malware) to `CVE-1950-3333` (Vulnerability)';
    const notificationMessageFrom = '[relationship] Restricted exploits CVE-1950-3333';
    const resultMessageFrom = '`admin` deletes the relation exploits from `Restricted` to `CVE-1950-3333` (Vulnerability)';
    expect(restrictedStreamMessageForRelationship(streamMessageFrom, notificationMessageFrom)).toEqual(resultMessageFrom);
    // to is restricted
    const streamMessageTo = '`admin` deletes the relation uses from `MyCampaign` (Campaign) to `Paradise Ransomware` (Malware)';
    const notificationMessageTo = '[relationship] MyCampaign uses Restricted';
    const resultMessageTo = '`admin` deletes the relation uses from `MyCampaign` (Campaign) to `Restricted`';
    expect(restrictedStreamMessageForRelationship(streamMessageTo, notificationMessageTo)).toEqual(resultMessageTo);
  });
});
