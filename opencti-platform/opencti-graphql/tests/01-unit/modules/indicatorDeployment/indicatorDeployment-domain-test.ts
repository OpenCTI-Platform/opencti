import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import {
  computeDeploymentChange,
  computeIndicatorDeploymentCounters,
  computeProvenShare,
  hitsSightingStixId,
  resolveEffectiveStatus,
} from '../../../../src/modules/indicatorDeployment/indicatorDeployment-domain';
import { extractDeploymentIndicatorIds } from '../../../../src/manager/indicatorDeploymentManager';
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
});

describe('derived counters', () => {
  it('should count live, failed, proven and hit deployments', () => {
    const counters = computeIndicatorDeploymentCounters([
      { deployment_status: 'deployed', validation_status: 'detected', hit_count: 0 },
      { deployment_status: 'active', validation_status: 'missed', hit_count: 3 },
      { deployment_status: 'failed', validation_status: 'not_requested' },
      { deployment_status: 'removed', validation_status: 'prevented', hit_count: 1 },
      { deployment_status: 'expired', validation_status: 'requested' },
    ]);
    expect(counters).toEqual({
      deployment_platforms_count: 2,
      deployment_failed_count: 1,
      validated_platforms_count: 2,
      hit_platforms_count: 2,
    });
  });
  it('should return zeros without deployment', () => {
    expect(computeIndicatorDeploymentCounters([])).toEqual({
      deployment_platforms_count: 0,
      deployment_failed_count: 0,
      validated_platforms_count: 0,
      hit_platforms_count: 0,
    });
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
});
