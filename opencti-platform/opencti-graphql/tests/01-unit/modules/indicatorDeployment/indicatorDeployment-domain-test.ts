import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import {
  addHits,
  computeDeploymentChange,
  computeIndicatorDeploymentCounters,
  computeHitsSightingValues,
  computeProvenShare,
  HIT_COUNT_MAX,
  HIT_REPORT_IDS_MAX,
  hitReportIdsAfter,
  isHitsReplay,
  isHitsSightingUpToDate,
  isRemovalOverdue,
  isRemovalRequested,
  resolveEffectiveStatus,
} from '../../../../src/modules/indicatorDeployment/indicatorDeployment-domain';
import {
  extractAccessChangedEndpoints,
  extractDeploymentIndicatorIds,
  extractIndicatorRevocations,
  extractStreamedDeploymentLive,
  hasSecurityPlatformRemoval,
} from '../../../../src/manager/indicatorDeploymentManager';
import { hitsSightingStixId, isPairReadableByReporter, pairOrganizations } from '../../../../src/modules/indicatorDeployment/indicatorDeployment-utils';
import type { DataEvent, SseEvent } from '../../../../src/types/event';

const NOW = new Date('2026-10-03T12:00:00.000Z');

describe('resolveEffectiveStatus', () => {
  it('should never downgrade an active deployment on a re-push', () => {
    expect(resolveEffectiveStatus('active', 'deployed')).toEqual('active');
  });
  it('should never downgrade a live deployment to pending', () => {
    expect(resolveEffectiveStatus('deployed', 'pending')).toEqual('deployed');
    expect(resolveEffectiveStatus('active', 'pending')).toEqual('active');
  });
  it('should apply every other reported status', () => {
    expect(resolveEffectiveStatus('active', 'failed')).toEqual('failed');
    expect(resolveEffectiveStatus('failed', 'deployed')).toEqual('deployed');
    expect(resolveEffectiveStatus('expired', 'removed')).toEqual('removed');
    expect(resolveEffectiveStatus(undefined, 'pending')).toEqual('pending');
  });
});

describe('computeDeploymentChange on creation', () => {
  it('should create a deployed relationship with deployed_at and last_sync_at', () => {
    const change = computeDeploymentChange(undefined, { status: 'deployed', externalId: 'ti-1' }, NOW);
    expect(change.meaningful).toEqual(true);
    expect(change.attributes).toEqual({ deployment_status: 'deployed', external_id: 'ti-1', deployed_at: NOW, last_sync_at: NOW });
  });
  it('should keep the vendor error on failure', () => {
    const change = computeDeploymentChange(undefined, { status: 'failed', errorMessage: 'quota exceeded' }, NOW);
    expect(change.attributes).toEqual({ deployment_status: 'failed', error_message: 'quota exceeded', last_sync_at: NOW });
  });
  it('should use reported dates', () => {
    const change = computeDeploymentChange(undefined, { status: 'removed', removedAt: '2026-10-01T00:00:00.000Z', syncedAt: '2026-10-02T00:00:00.000Z' }, NOW);
    expect(change.attributes.removed_at).toEqual(new Date('2026-10-01T00:00:00.000Z'));
    expect(change.attributes.last_sync_at).toEqual(new Date('2026-10-02T00:00:00.000Z'));
  });
  it('should reject expired, unknown statuses, invalid dates and oversized values', () => {
    expect(() => computeDeploymentChange(undefined, { status: 'expired' }, NOW)).toThrow();
    expect(() => computeDeploymentChange(undefined, { status: 'live' as never }, NOW)).toThrow();
    expect(() => computeDeploymentChange(undefined, { status: 'deployed', deployedAt: 'not a date' }, NOW)).toThrow();
    expect(() => computeDeploymentChange(undefined, { status: 'deployed', externalId: 'x'.repeat(1001) }, NOW)).toThrow();
  });
});

describe('computeDeploymentChange on update', () => {
  it('should only refresh last_sync_at when nothing changed (heartbeat)', () => {
    const current = { deployment_status: 'active' as const, external_id: 'ti-1', deployed_at: '2026-09-01T00:00:00.000Z' };
    const change = computeDeploymentChange(current, { status: 'deployed', externalId: 'ti-1' }, NOW);
    expect(change.meaningful).toEqual(false);
    expect(change.attributes).toEqual({ last_sync_at: NOW });
  });
  it('should record a re-deployment after a removal', () => {
    const current = { deployment_status: 'removed' as const, deployed_at: '2026-09-01T00:00:00.000Z', removed_at: '2026-09-10T00:00:00.000Z' };
    const change = computeDeploymentChange(current, { status: 'deployed' }, NOW);
    expect(change.meaningful).toEqual(true);
    expect(change.attributes).toEqual({ deployment_status: 'deployed', deployed_at: NOW, removed_at: null, last_sync_at: NOW });
  });
  it('should set removed_at once and clear a stale error when status leaves failed', () => {
    const removed = computeDeploymentChange({ deployment_status: 'active', deployed_at: '2026-09-01T00:00:00.000Z' }, { status: 'removed' }, NOW);
    expect(removed.attributes).toEqual({ deployment_status: 'removed', removed_at: NOW, last_sync_at: NOW });
    const recovered = computeDeploymentChange({ deployment_status: 'failed', error_message: 'boom' }, { status: 'active' }, NOW);
    expect(recovered.attributes).toEqual({ deployment_status: 'active', deployed_at: NOW, error_message: null, last_sync_at: NOW });
  });
  it('should update the external id and the error message when they change', () => {
    const change = computeDeploymentChange({ deployment_status: 'failed', error_message: 'old' }, { status: 'failed', errorMessage: 'new', externalId: 'x' }, NOW);
    expect(change.attributes).toEqual({ external_id: 'x', error_message: 'new', last_sync_at: NOW });
  });
  it('should ignore a delayed report synchronized before the last applied one', () => {
    const current = {
      deployment_status: 'removed' as const,
      deployed_at: '2026-09-01T00:00:00.000Z',
      removed_at: '2026-10-03T10:00:00.000Z',
      last_sync_at: '2026-10-03T10:00:00.000Z',
    };
    const change = computeDeploymentChange(current, { status: 'deployed', externalId: 'ti-2', syncedAt: '2026-10-03T09:00:00.000Z' }, NOW);
    expect(change).toEqual({ attributes: {}, meaningful: false, stale: true });
  });
  it('should apply a report synchronized at the same time as the last applied one or later', () => {
    const current = { deployment_status: 'deployed' as const, deployed_at: '2026-09-01T00:00:00.000Z', last_sync_at: '2026-10-03T10:00:00.000Z' };
    const same = computeDeploymentChange(current, { status: 'removed', syncedAt: '2026-10-03T10:00:00.000Z' }, NOW);
    expect(same.stale).toEqual(false);
    expect(same.attributes.deployment_status).toEqual('removed');
    const later = computeDeploymentChange(current, { status: 'failed', errorMessage: 'gone', syncedAt: '2026-10-03T11:00:00.000Z' }, NOW);
    expect(later.attributes).toEqual({ deployment_status: 'failed', error_message: 'gone', last_sync_at: new Date('2026-10-03T11:00:00.000Z') });
  });
  it('should store the platform time for a report synchronized in the future', () => {
    const change = computeDeploymentChange(undefined, { status: 'deployed', syncedAt: '2026-10-03T18:00:00.000Z' }, NOW);
    expect(change.attributes.last_sync_at).toEqual(NOW);
    const next = computeDeploymentChange({ deployment_status: 'deployed', deployed_at: NOW, last_sync_at: NOW }, { status: 'removed' }, NOW);
    expect(next.stale).toEqual(false);
    expect(next.attributes.deployment_status).toEqual('removed');
  });
});

describe('derived counters', () => {
  it('should count reported, live, failed, expired, proven and hit deployments', () => {
    const syncedAt = '2026-10-01T00:00:00.000Z';
    const counters = computeIndicatorDeploymentCounters([
      { deployment_status: 'deployed', validation_status: 'detected', hit_count: 0, last_sync_at: syncedAt },
      { deployment_status: 'active', validation_status: 'missed', hit_count: 3, last_sync_at: syncedAt },
      { deployment_status: 'failed', validation_status: 'not_requested', last_sync_at: syncedAt },
      { deployment_status: 'removed', validation_status: 'prevented', hit_count: 1, last_sync_at: syncedAt },
      { deployment_status: 'expired', validation_status: 'requested', last_sync_at: syncedAt },
      { deployment_status: 'pending', last_sync_at: syncedAt },
    ]);
    expect(counters).toEqual({
      deployments_count: 6,
      deployment_platforms_count: 2,
      deployment_failed_count: 1,
      deployment_expired_count: 1,
      validated_platforms_count: 2,
      hit_platforms_count: 2,
    });
  });
  it('should return zeros without deployment', () => {
    expect(computeIndicatorDeploymentCounters([])).toEqual({
      deployments_count: 0,
      deployment_platforms_count: 0,
      deployment_failed_count: 0,
      deployment_expired_count: 0,
      validated_platforms_count: 0,
      hit_platforms_count: 0,
    });
  });
  it('should not count as disseminated a pending deployment no connector reported', () => {
    expect(computeIndicatorDeploymentCounters([{ deployment_status: 'pending' }]).deployments_count).toEqual(0);
  });
  it('should compute the proven share as a percentage with one decimal', () => {
    expect(computeProvenShare(0, 0)).toEqual(0);
    expect(computeProvenShare(3, 1)).toEqual(33.3);
    expect(computeProvenShare(4, 4)).toEqual(100);
  });
});

describe('hits sighting identifier', () => {
  it('should be stable per indicator and platform', () => {
    const first = hitsSightingStixId('indicator-a', 'platform-b');
    expect(first).toMatch(/^sighting--[0-9a-f-]{36}$/);
    expect(hitsSightingStixId('indicator-a', 'platform-b')).toEqual(first);
    expect(hitsSightingStixId('indicator-a', 'platform-c')).not.toEqual(first);
  });
});

describe('hits sighting values', () => {
  const FIRST = new Date('2026-10-01T08:00:00.000Z');
  const LAST = new Date('2026-10-03T10:00:00.000Z');
  const REPORT_FIRST = new Date('2026-10-03T09:00:00.000Z');
  const deployment = { hit_count: 12, first_hit_at: FIRST, last_hit_at: LAST };

  it('should rebuild a missing sighting from the deployment, original first hit included', () => {
    expect(computeHitsSightingValues(undefined, deployment, 0, REPORT_FIRST, LAST)).toEqual({ attribute_count: 12, first_seen: FIRST, last_seen: LAST });
  });
  it('should stop the hit counts at the largest 32-bit integer instead of overflowing them', () => {
    expect(addHits(HIT_COUNT_MAX - 1, 1)).toEqual(HIT_COUNT_MAX);
    expect(addHits(HIT_COUNT_MAX, 5)).toEqual(HIT_COUNT_MAX);
    expect(addHits(10, 5)).toEqual(15);
    const full = { attribute_count: HIT_COUNT_MAX - 2, first_seen: FIRST.toISOString(), last_seen: LAST.toISOString() };
    expect(computeHitsSightingValues(full, { ...deployment, hit_count: HIT_COUNT_MAX }, 7, REPORT_FIRST, LAST).attribute_count).toEqual(HIT_COUNT_MAX);
  });
  it('should repair a sighting left behind by a failed write on a replay', () => {
    const stale = { attribute_count: 7, first_seen: FIRST.toISOString(), last_seen: '2026-10-02T10:00:00.000Z' };
    const values = computeHitsSightingValues(stale, deployment, 0, REPORT_FIRST, LAST);
    expect(values).toEqual({ attribute_count: 12, first_seen: FIRST, last_seen: LAST });
    expect(isHitsSightingUpToDate(stale, values)).toEqual(false);
  });
  it('should add the new hits to a consistent sighting and never decrease a larger count', () => {
    const consistent = { attribute_count: 9, first_seen: FIRST, last_seen: new Date('2026-10-02T10:00:00.000Z') };
    expect(computeHitsSightingValues(consistent, deployment, 3, REPORT_FIRST, LAST).attribute_count).toEqual(12);
    const larger = { attribute_count: 40, first_seen: new Date('2026-09-01T00:00:00.000Z'), last_seen: LAST };
    const values = computeHitsSightingValues(larger, deployment, 0, REPORT_FIRST, LAST);
    expect(values).toEqual({ attribute_count: 40, first_seen: larger.first_seen, last_seen: LAST });
    expect(isHitsSightingUpToDate(larger, values)).toEqual(true);
  });
  it('should fall back to the report dates for a deployment without first hit', () => {
    const values = computeHitsSightingValues(undefined, { hit_count: 2 }, 2, REPORT_FIRST, LAST);
    expect(values).toEqual({ attribute_count: 2, first_seen: REPORT_FIRST, last_seen: LAST });
  });
});

describe('hits report replay', () => {
  const AT = new Date('2026-10-01T10:00:00.000Z');
  const BEFORE = new Date('2026-10-01T09:00:00.000Z');
  const AFTER = new Date('2026-10-01T11:00:00.000Z');
  it('should use the last hit as the watermark', () => {
    expect(isHitsReplay(undefined, AT)).toEqual(false);
    expect(isHitsReplay({ last_hit_at: null }, AT)).toEqual(false);
    expect(isHitsReplay({ last_hit_at: AT }, BEFORE, 'report-b')).toEqual(true);
    expect(isHitsReplay({ last_hit_at: AT }, AFTER)).toEqual(false);
  });
  it('should tell apart the reports ending at the last known hit by their report id', () => {
    const deployment = { last_hit_at: AT.toISOString(), last_hit_report_ids: ['report-a'] };
    expect(isHitsReplay(deployment, AT)).toEqual(true);
    expect(isHitsReplay(deployment, AT, 'report-a')).toEqual(true);
    expect(isHitsReplay(deployment, AT, 'report-b')).toEqual(false);
  });
  it('should keep the report ids counted at the last hit only', () => {
    const deployment = { last_hit_at: AT, last_hit_report_ids: ['report-a'] };
    expect(hitReportIdsAfter(undefined, AT, 'report-a')).toEqual(['report-a']);
    expect(hitReportIdsAfter(deployment, AT, 'report-b')).toEqual(['report-a', 'report-b']);
    expect(hitReportIdsAfter(deployment, AFTER, 'report-c')).toEqual(['report-c']);
    expect(hitReportIdsAfter(deployment, AFTER)).toEqual([]);
    // An id is never evicted while its instant is the watermark: a report beyond the limit is refused instead
    const full = { last_hit_at: AT, last_hit_report_ids: Array.from({ length: HIT_REPORT_IDS_MAX }, (_, i) => `report-${i}`) };
    expect(() => hitReportIdsAfter(full, AT, 'report-new')).toThrow(`At most ${HIT_REPORT_IDS_MAX} distinct hit reports`);
    expect(isHitsReplay(full, AT, 'report-0')).toEqual(true);
    // A later instant starts again
    expect(hitReportIdsAfter(full, AFTER, 'report-new')).toEqual(['report-new']);
  });
});

describe('deployment manager stream extraction', () => {
  const event = (data: Record<string, unknown>) => ({ id: '1', event: 'update', data: { type: 'update', data } }) as unknown as SseEvent<DataEvent>;
  it('should extract the indicators of deployed-on events only', () => {
    const ext = 'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba';
    const ids = extractDeploymentIndicatorIds([
      event({ type: 'relationship', relationship_type: 'deployed-on', extensions: { [ext]: { source_ref: 'ind-1' } } }),
      event({ type: 'relationship', relationship_type: 'deployed-on', extensions: { [ext]: { source_ref: 'ind-1' } } }),
      event({ type: 'relationship', relationship_type: 'uses', extensions: { [ext]: { source_ref: 'ind-2' } } }),
      event({ type: 'indicator', extensions: { [ext]: { id: 'ind-3' } } }),
    ]);
    expect(ids).toEqual(['ind-1']);
  });
  it('should refresh the surviving indicator of a merge', () => {
    const ext = 'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba';
    const merge = (data: Record<string, unknown>) => ({ id: '1', event: 'merge', data: { type: 'merge', data } }) as unknown as SseEvent<DataEvent>;
    expect(extractDeploymentIndicatorIds([
      merge({ type: 'indicator', extensions: { [ext]: { id: 'survivor', type: 'Indicator' } } }),
      merge({ type: 'malware', extensions: { [ext]: { id: 'malware-1', type: 'Malware' } } }),
      event({ type: 'indicator', extensions: { [ext]: { id: 'updated', type: 'Indicator' } } }),
    ])).toEqual(['survivor']);
  });
  it('should detect a security platform deleted or merged away', () => {
    const ext = 'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba';
    const platform = { type: 'identity', extensions: { [ext]: { type: 'SecurityPlatform' } } };
    const typed = (type: string, data: Record<string, unknown>) => ({ id: '1', event: type, data: { type, data } }) as unknown as SseEvent<DataEvent>;
    expect(hasSecurityPlatformRemoval([typed('delete', platform)])).toEqual(true);
    expect(hasSecurityPlatformRemoval([typed('merge', platform)])).toEqual(true);
    expect(hasSecurityPlatformRemoval([typed('update', platform)])).toEqual(false);
    expect(hasSecurityPlatformRemoval([typed('delete', { type: 'identity', extensions: { [ext]: { type: 'Organization' } } })])).toEqual(false);
    expect(hasSecurityPlatformRemoval([])).toEqual(false);
  });
  it('should collect the indicators and security platforms whose markings or sharing changed', () => {
    const ext = 'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba';
    const update = (data: Record<string, unknown>, path: string) => ({
      id: '1',
      event: 'update',
      data: { type: 'update', data, context: { patch: [{ op: 'add', path }] } },
    }) as unknown as SseEvent<DataEvent>;
    const changes = extractAccessChangedEndpoints([
      update({ type: 'identity', extensions: { [ext]: { id: 'platform-1', type: 'SecurityPlatform' } } }, '/object_marking_refs/0'),
      update({ type: 'indicator', extensions: { [ext]: { id: 'indicator-1', type: 'Indicator' } } }, '/object_marking_refs'),
      update({ type: 'indicator', extensions: { [ext]: { id: 'indicator-3', type: 'Indicator', granted_refs: [] } } }, '/extensions/' + ext + '/granted_refs/0'),
      ({ id: '2', event: 'merge', data: { type: 'merge', data: { type: 'identity', extensions: { [ext]: { id: 'platform-2', type: 'SecurityPlatform' } } }, context: { patch: [{ op: 'add', path: '/object_marking_refs/1' }] } } }) as unknown as SseEvent<DataEvent>,
      // Other changes and other types are ignored
      update({ type: 'indicator', extensions: { [ext]: { id: 'indicator-2', type: 'Indicator' } } }, '/x_opencti_score'),
      update({ type: 'identity', extensions: { [ext]: { id: 'organization-1', type: 'Organization' } } }, '/object_marking_refs/0'),
      update({ type: 'indicator', extensions: { [ext]: { id: 'indicator-4', type: 'Indicator' } } }, '/extensions/' + ext + '/authorized_members/0'),
      update({ type: 'relationship', relationship_type: 'deployed-on', extensions: { [ext]: { id: 'deployment-1', source_ref: 'indicator-5' } } }, '/object_marking_refs/0'),
      // With organization sharing enforced, an individual creator reads the deployments it created
      update({ type: 'indicator', extensions: { [ext]: { id: 'indicator-6', type: 'Indicator' } } }, '/created_by_ref'),
      // A merge moves the pair relationships of the merged elements to the target, whatever its own fields
      ({ id: '3', event: 'merge', data: { type: 'merge', data: { type: 'identity', extensions: { [ext]: { id: 'platform-3', type: 'SecurityPlatform' } } }, context: { patch: [] } } }) as unknown as SseEvent<DataEvent>,
    ]);
    expect(changes).toEqual({ indicatorIds: ['indicator-1', 'indicator-3', 'indicator-4', 'indicator-5', 'indicator-6'], platformIds: ['platform-1', 'platform-2', 'platform-3'] });
    expect(extractAccessChangedEndpoints([])).toEqual({ indicatorIds: [], platformIds: [] });
  });
  it('should read whether the last event of each indicator showed it live on a platform', () => {
    const ext = 'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba';
    const typed = (type: string, data: Record<string, unknown>) => ({ id: '1', event: type, data: { type, data } }) as unknown as SseEvent<DataEvent>;
    const indicator = (id: string, count?: number) => ({ type: 'indicator', extensions: { [ext]: { id, type: 'Indicator', deployment_platforms_count: count } } });
    const shown = extractStreamedDeploymentLive([
      typed('update', indicator('indicator-1', 2)),
      typed('update', indicator('indicator-1')), // the later event wins
      typed('create', indicator('indicator-2', 1)),
      typed('delete', indicator('indicator-3', 1)),
      typed('update', { type: 'relationship', relationship_type: 'deployed-on', extensions: { [ext]: { id: 'deployment-1', source_ref: 'indicator-4' } } }),
    ]);
    expect([...shown.entries()]).toEqual([['indicator-1', false], ['indicator-2', true]]);
  });
  it('should collect the indicators revoked by an update, at the time of their last revocation event', () => {
    const ext = 'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba';
    const update = (eventId: string, id: string, revoked: boolean, path: string, type = 'Indicator') => ({
      id: eventId,
      event: 'update',
      data: { type: 'update', data: { type: 'indicator', revoked, extensions: { [ext]: { id, type } } }, context: { patch: [{ op: 'replace', path }] } },
    }) as unknown as SseEvent<DataEvent>;
    const revocations = extractIndicatorRevocations([
      update('1790000000000-0', 'indicator-1', true, '/revoked'),
      update('1790000060000-0', 'indicator-1', true, '/revoked'),
      update('1790000000000-1', 'indicator-2', false, '/revoked'), // reinstated
      update('1790000000000-2', 'indicator-3', true, '/x_opencti_score'), // already revoked, other change
      update('1790000000000-3', 'malware-1', true, '/revoked', 'Malware'),
    ]);
    expect([...revocations.entries()]).toEqual([['indicator-1', new Date(1790000060000).toISOString()]]);
    expect(extractIndicatorRevocations([]).size).toEqual(0);
  });
});

describe('sharing of the pair relationships', () => {
  it('should share with the organizations both ends are shared with only', () => {
    expect(pairOrganizations({ granted: ['org-a', 'org-b'] }, { granted: ['org-b', 'org-c'] })).toEqual(['org-b']);
    expect(pairOrganizations({ granted: ['org-a'] }, { granted: ['org-b'] })).toEqual([]);
    expect(pairOrganizations({ granted: ['org-a'] }, {})).toEqual([]);
    expect(pairOrganizations({}, { granted: ['org-a'] })).toEqual([]);
    expect(pairOrganizations({ granted: ['org-a', 'org-a'] }, { granted: ['org-a'] })).toEqual(['org-a']);
  });
  it('should let a reporting account report only on the pairs it reads back', () => {
    expect(isPairReadableByReporter([], { insidePlatformOrganization: true, organizationIds: [] })).toEqual(true);
    expect(isPairReadableByReporter(['org-b'], { insidePlatformOrganization: false, organizationIds: ['org-a', 'org-b'] })).toEqual(true);
    expect(isPairReadableByReporter([], { insidePlatformOrganization: false, organizationIds: ['org-a', 'org-b'] })).toEqual(false);
    expect(isPairReadableByReporter(['org-c'], { insidePlatformOrganization: false, organizationIds: ['org-a'] })).toEqual(false);
  });
});

describe('expiry of live deployments', () => {
  const threshold = '2026-10-03T00:00:00.000Z';
  const requestedBefore = { removal_requested_at: '2026-10-02T00:00:00.000Z' };
  const requestedWithin = { removal_requested_at: '2026-10-03T12:00:00.000Z' };
  it('should request the removal of a withdrawn deployment or of a deployment of a revoked indicator', () => {
    expect(isRemovalRequested({ revoked: true })).toEqual(true);
    expect(isRemovalRequested({}, { revoked: true })).toEqual(true);
    expect(isRemovalRequested({ revoked: false }, { revoked: false })).toEqual(false);
    expect(isRemovalRequested({})).toEqual(false);
  });
  it('should flag a deployment once its indicator is past its validity, whatever the deployment records', () => {
    expect(isRemovalOverdue({}, { valid_until: '2026-10-01T00:00:00.000Z' }, threshold)).toEqual(true);
    expect(isRemovalOverdue({}, { valid_until: '2026-10-05T00:00:00.000Z' }, threshold)).toEqual(false);
  });
  it('should count the grace period of a requested removal from the time it was requested, never from a later edit', () => {
    expect(isRemovalOverdue(requestedBefore, { revoked: true }, threshold)).toEqual(true);
    expect(isRemovalOverdue({ revoked: true, ...requestedBefore }, { revoked: false }, threshold)).toEqual(true);
    // Requested within the grace period: the connector still has time to confirm the removal
    expect(isRemovalOverdue(requestedWithin, { revoked: true }, threshold)).toEqual(false);
    // A revocation the deployment manager has not recorded yet starts its grace period when it records it
    const revokedAndEditedLongAgo = { revoked: true, updated_at: '2026-10-01T00:00:00.000Z' };
    expect(isRemovalOverdue({}, revokedAndEditedLongAgo, threshold)).toEqual(false);
    // A removal no longer requested (indicator reinstated) is never flagged on the time it was requested
    expect(isRemovalOverdue(requestedBefore, { revoked: false }, threshold)).toEqual(false);
    expect(isRemovalOverdue({}, undefined, threshold)).toEqual(false);
  });
});
