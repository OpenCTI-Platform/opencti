import { describe, expect, it } from 'vitest';
import { ruleApplyLockId, ruleRescanLockId } from '../../../src/manager/ruleManager';

describe('Rule async lock ids', () => {
  it('should share the apply lock between messages applying the same rule on the same element', () => {
    // The lock id does not depend on the execution: duplicate messages of an element wait for each other
    expect(ruleApplyLockId('element-a', 'rule-a')).toEqual(ruleApplyLockId('element-a', 'rule-a'));
  });

  it('should not share the apply lock between rules or between elements', () => {
    const lockId = ruleApplyLockId('element-a', 'rule-a');
    expect(ruleApplyLockId('element-a', 'rule-b')).not.toEqual(lockId);
    expect(ruleApplyLockId('element-b', 'rule-a')).not.toEqual(lockId);
  });

  it('should lock rescans per element', () => {
    expect(ruleRescanLockId('element-a')).toEqual(ruleRescanLockId('element-a'));
    expect(ruleRescanLockId('element-b')).not.toEqual(ruleRescanLockId('element-a'));
  });
});
