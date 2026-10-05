import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import DefenseScopeToolbar from './DefenseScopeToolbar';
import { DEFAULT_DEFENSE_SCOPE } from './defenseMatrix-utils';

const PLATFORMS = [
  { id: 'platform-siem', name: 'SIEM', entity_type: 'SecurityPlatform' },
  { id: 'platform-edr', name: 'EDR', entity_type: 'SecurityPlatform' },
];

describe('Defense scope toolbar', () => {
  it('drops the saved platforms that are no longer available', () => {
    const onScopeChange = vi.fn();
    const scope = { ...DEFAULT_DEFENSE_SCOPE, platformIds: ['platform-edr', 'platform-deleted'] };
    testRender(<DefenseScopeToolbar platforms={PLATFORMS} scope={scope} onScopeChange={onScopeChange} />);
    expect(onScopeChange).toHaveBeenCalledTimes(1);
    expect(onScopeChange).toHaveBeenCalledWith({ ...scope, platformIds: ['platform-edr'] });
  });
  it('keeps a scope whose platforms are all available', () => {
    const onScopeChange = vi.fn();
    const scope = { ...DEFAULT_DEFENSE_SCOPE, platformIds: ['platform-edr', 'platform-siem'] };
    testRender(<DefenseScopeToolbar platforms={PLATFORMS} scope={scope} onScopeChange={onScopeChange} />);
    expect(onScopeChange).not.toHaveBeenCalled();
  });
  it('keeps the scope of a view bound to one platform', () => {
    const onScopeChange = vi.fn();
    const scope = { ...DEFAULT_DEFENSE_SCOPE, platformIds: ['platform-edr'] };
    testRender(<DefenseScopeToolbar platforms={[]} hidePlatforms scope={scope} onScopeChange={onScopeChange} />);
    expect(onScopeChange).not.toHaveBeenCalled();
  });
});
