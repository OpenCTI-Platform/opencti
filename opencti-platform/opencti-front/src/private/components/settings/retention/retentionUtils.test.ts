import { describe, expect, it } from 'vitest';
import { isDeletableRetentionRule } from './retentionUtils';

describe('isDeletableRetentionRule', () => {
  it.each(['knowledge', 'conflicts', null, undefined])('allows deleting a %s policy', (scope) => {
    expect(isDeletableRetentionRule(scope)).toBe(true);
  });

  it.each(['file', 'workbench', 'history', 'activity'])('keeps the %s policy of the platform', (scope) => {
    expect(isDeletableRetentionRule(scope)).toBe(false);
  });
});
