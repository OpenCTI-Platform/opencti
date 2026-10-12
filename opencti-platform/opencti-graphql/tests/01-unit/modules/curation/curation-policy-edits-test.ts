import { describe, expect, it } from 'vitest';
import { applyPolicyEdits, validatePolicyInput } from '../../../../src/modules/curation/curation-policies';
import { EditOperation } from '../../../../src/generated/graphql';

const policy = { name: 'Alias policy', policy_kinds: ['alias'], policy_entity_types: ['Intrusion-Set'], auto_apply_threshold: 0.9 };

describe('curation policy edits', () => {
  it('produces the policy the platform will store, operation by operation', () => {
    expect(applyPolicyEdits(policy, [
      { key: 'policy_kinds', value: ['merge'], operation: EditOperation.Add },
      { key: 'policy_entity_types', value: ['Intrusion-Set'], operation: EditOperation.Remove },
      { key: 'auto_apply_threshold', value: [0.95] },
    ])).toEqual({ name: 'Alias policy', policy_kinds: ['alias', 'merge'], policy_entity_types: [], auto_apply_threshold: 0.95 });
  });

  it('empties a kind list or a value the edit removes, for the validation to refuse it', () => {
    const next = applyPolicyEdits(policy, [
      { key: 'policy_kinds', value: ['alias'], operation: EditOperation.Remove },
      { key: 'auto_apply_threshold', value: [], operation: EditOperation.Remove },
    ]);
    expect(next.policy_kinds).toEqual([]);
    expect(next.auto_apply_threshold).toBeUndefined();
  });

  it('refuses a switch of the policy an edit sets to anything but true or false', () => {
    ['policy_enabled', 'forbid_open_contradiction', 'require_adjudication'].forEach((key) => {
      ['false', 1, ['true']].forEach((value) => {
        const next = applyPolicyEdits({ ...policy, [key]: true }, [{ key, value: [value] }]);
        expect(() => validatePolicyInput(next)).toThrow('take true or false');
      });
      expect(() => validatePolicyInput(applyPolicyEdits({ ...policy, [key]: true }, [{ key, value: [false] }]))).not.toThrow();
    });
  });
});
