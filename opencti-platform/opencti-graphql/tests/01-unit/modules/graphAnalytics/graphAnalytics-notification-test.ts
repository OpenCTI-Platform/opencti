import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { buildClusterJoinedMessage, CLUSTER_JOINED_NOTIFICATION_MAX, GRAPH_TRIGGER_CLUSTER_JOINED } from '../../../../src/modules/graphAnalytics/graphAnalytics-notification';
import { TRIGGER_EVENT_TYPES_VALUES } from '../../../../src/manager/notificationManager';

describe('graph analytics notifications', () => {
  it('should register the cluster joined event among the live trigger events', () => {
    expect(GRAPH_TRIGGER_CLUSTER_JOINED).toBe('graph_cluster_joined');
    expect(TRIGGER_EVENT_TYPES_VALUES).toContain('graph_cluster_joined');
  });

  it('should only name the entity and the cluster, never member counts', () => {
    const message = buildClusterJoinedMessage('198.51.100.7', 'Infrastructure cluster 3fa85f64');
    expect(message).toBe('[graph analytics] `198.51.100.7` joined the cluster `Infrastructure cluster 3fa85f64`');
    expect(message).not.toMatch(/\d+ members/);
  });

  it('should bound the notifications of one run', () => {
    expect(CLUSTER_JOINED_NOTIFICATION_MAX).toBe(1000);
  });
});
