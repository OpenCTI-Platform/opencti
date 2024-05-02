import { describe, it, expect } from 'vitest';
import { onSupportPackageMessage } from '../../../src/listener/supportPackageListener';
import { findById as findPackageById, prepareNewSupportPackage } from '../../../src/modules/support/support-domain';
import { ADMIN_USER } from '../../utils/testQuery';
import type { AuthContext } from '../../../src/types/user';
import type { BasicStoreEntity } from '../../../src/types/store';
import type { BasicStoreEntityDecayRule } from '../../../src/modules/decayRule/decayRule-types';

const adminContext: AuthContext = { user: ADMIN_USER, tracing: undefined, source: 'supportPackageListener-test', otp_mandatory: false };
describe('SupportPackage listener standard behavior', () => {
  it('should support package event update node status', async () => {
    const supportPackage = await prepareNewSupportPackage(adminContext, ADMIN_USER, { name: 'test listener support package' });

    await onSupportPackageMessage({ instance: supportPackage });

    const supportPackageEntity = await findPackageById(adminContext, ADMIN_USER, supportPackage.id);
    expect(supportPackageEntity.nodes_status.length).toBe(1);
  });
});

describe('SupportPackage listener error management', () => {
  it('should entity does it not support package be ignored', async () => {
    const wrongEntity: Partial<BasicStoreEntityDecayRule> = {
      id: 'testing-errors'
    };
    await onSupportPackageMessage({ instance: wrongEntity as BasicStoreEntity });
    // expecting no error throw.
  });
});
