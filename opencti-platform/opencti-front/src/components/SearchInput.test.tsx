import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../utils/tests/test-render';
import SearchInput from './SearchInput';

// The top bar search with AI available, without XTM One (no agent picker)
vi.mock('../utils/hooks/useEnterpriseEdition', () => ({ default: () => true }));
vi.mock('../utils/hooks/useAI', () => ({ default: () => ({ enabled: true, configured: true, fullyActive: true }) }));
vi.mock('../private/components/chatbox/ChatbotContext', () => ({ useChatbot: () => ({ xtmOneConfigured: false }) }));
vi.mock('../utils/hooks/useGranted', () => ({ default: () => false, SETTINGS_SETPARAMETERS: 'SETTINGS_SETPARAMETERS' }));
vi.mock('../utils/hooks/useAuth', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../utils/hooks/useAuth')>()),
  default: () => ({ settings: { id: 'settings-id' } }),
}));
vi.mock('../utils/ai/agentApi', () => ({ fetchAgentsForIntent: () => Promise.resolve([]) }));
// Relay-bound dialogs, closed and irrelevant here
vi.mock('../private/components/common/entreprise_edition/EnterpriseEditionAgreement', () => ({ default: () => null }));
vi.mock('../private/components/settings/ValidateTermsOfUseDialog', () => ({ default: () => null }));
vi.mock('../private/components/cases/feedbacks/FeedbackCreation', () => ({ default: () => null }));

describe('SearchInput (top bar)', () => {
  it('names every mode toggle, including the icon-only AI toggle', () => {
    testRender(<SearchInput variant="topBar" onSubmit={vi.fn()} keyword="" />);

    expect(screen.getByRole('button', { name: 'Advanced search' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Bulk search' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Ask AI' })).toHaveAttribute('aria-pressed', 'false');
  });
});
