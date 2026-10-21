import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import { Route, Routes } from 'react-router';
import testRender from '../../../../utils/tests/test-render';
import useHelper from '../../../../utils/hooks/useHelper';
import DecayRuleTabs from './DecayRuleTabs';
import KnowledgeDecayRulesLink from './KnowledgeDecayRulesLink';
import { DECAY_RULES_PATH } from './decayRuleTabState';

vi.mock('../../../../utils/hooks/useHelper', () => ({
  default: vi.fn(),
}));

// The tabs run their list queries as soon as they are mounted
vi.mock('@components/settings/decay/DecayRules', () => ({
  default: () => <div data-testid="decay-rules" />,
}));
vi.mock('./DecayExclusionRules', () => ({
  default: () => <div data-testid="decay-exclusion-rules" />,
}));
vi.mock('./KnowledgeDecayRules', () => ({
  default: () => <div data-testid="knowledge-decay-rules" />,
}));

const setProvenanceEnabled = (enabled: boolean) => {
  vi.mocked(useHelper).mockReturnValue({ isProvenanceEnabled: () => enabled } as unknown as ReturnType<typeof useHelper>);
};

// Follows the link of the Stale knowledge tab of the Curation hub to the decay rules page
const followKnowledgeDecayRulesLink = async () => {
  const { user } = testRender((
    <Routes>
      <Route path="/stale" element={<KnowledgeDecayRulesLink>Open the decay rules</KnowledgeDecayRulesLink>} />
      <Route path={DECAY_RULES_PATH} element={<DecayRuleTabs />} />
    </Routes>
  ), { route: '/stale' });
  await user.click(screen.getByRole('link', { name: 'Open the decay rules' }));
};

describe('Decay rule tabs', () => {
  afterEach(() => {
    window.history.pushState({}, '', '/');
  });

  it('opens the Knowledge decay rules tab from its link while provenance is enabled', async () => {
    setProvenanceEnabled(true);
    await followKnowledgeDecayRulesLink();
    expect(await screen.findByRole('tab', { name: 'Knowledge decay rules' })).toBeInTheDocument();
    expect(await screen.findByTestId('knowledge-decay-rules')).toBeInTheDocument();
  });

  it('has no Knowledge decay rules tab and never mounts it while provenance is disabled', async () => {
    setProvenanceEnabled(false);
    await followKnowledgeDecayRulesLink();
    expect(await screen.findByRole('tab', { name: 'Decay rules' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Decay exclusion rules' })).toBeInTheDocument();
    expect(screen.queryByRole('tab', { name: 'Knowledge decay rules' })).not.toBeInTheDocument();
    expect(await screen.findByTestId('decay-rules')).toBeInTheDocument();
    expect(screen.queryByTestId('knowledge-decay-rules')).not.toBeInTheDocument();
  });
});
