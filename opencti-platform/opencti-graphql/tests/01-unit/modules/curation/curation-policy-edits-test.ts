import { describe, expect, it } from 'vitest';
import { applyPolicyEdits } from '../../../../src/modules/curation/curation-policies';
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
});
