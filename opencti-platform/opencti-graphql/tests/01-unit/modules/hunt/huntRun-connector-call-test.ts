import { beforeEach, describe, expect, it, vi } from 'vitest';
import { listHuntConnectors } from '../../../../src/modules/hunt/hunt-dispatch';
import { isHuntRunConnectorCall } from '../../../../src/modules/hunt/huntRun/huntRun-domain';
import type { BasicStoreEntityHuntRun } from '../../../../src/modules/hunt/huntRun/huntRun-types';
import type { AuthUser } from '../../../../src/types/user';
import { testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/modules/hunt/hunt-dispatch', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-dispatch')>(),
  listHuntConnectors: vi.fn(),
}));

const run = { internal_id: 'run-1', connector_id: 'connector-1', connector_user_id: 'user-1', work_id: 'work-1' } as BasicStoreEntityHuntRun;
const user = (id: string) => ({ id } as AuthUser);
const connectorRunningAs = (userId: string) => vi.mocked(listHuntConnectors).mockResolvedValue([{ internal_id: 'connector-1', connector_user_id: userId }] as never);

describe('Hunt connector acting on a run', () => {
  beforeEach(() => {
    connectorRunningAs('user-1');
  });

  it('should accept the connector the run was dispatched to, in the work of the dispatch', async () => {
    expect(await isHuntRunConnectorCall(testContext, user('user-1'), run, 'work-1')).toBe(true);
    expect(await isHuntRunConnectorCall(testContext, user('user-1'), run, 'work-2')).toBe(false);
  });

  it('should refuse a connector registered again as another user since the dispatch, and its former user', async () => {
    connectorRunningAs('user-2');
    expect(await isHuntRunConnectorCall(testContext, user('user-2'), run, 'work-1')).toBe(false);
    expect(await isHuntRunConnectorCall(testContext, user('user-1'), run, 'work-1')).toBe(false);
  });

  it('should refuse the connector once it is registered again against another security platform than the one of the run', async () => {
    const onSplunk = { ...run, security_platform_id: 'platform-splunk' } as BasicStoreEntityHuntRun;
    const boundTo = (platformId: string) => vi.mocked(listHuntConnectors)
      .mockResolvedValue([{ internal_id: 'connector-1', connector_user_id: 'user-1', hunt_security_platform_id: platformId }] as never);
    boundTo('platform-splunk');
    expect(await isHuntRunConnectorCall(testContext, user('user-1'), onSplunk, 'work-1')).toBe(true);
    boundTo('platform-sentinel');
    expect(await isHuntRunConnectorCall(testContext, user('user-1'), onSplunk, 'work-1')).toBe(false);
  });

  it('should refuse a call on a run that records no connector user', async () => {
    expect(await isHuntRunConnectorCall(testContext, user('user-1'), { ...run, connector_user_id: null }, 'work-1')).toBe(false);
  });
});
