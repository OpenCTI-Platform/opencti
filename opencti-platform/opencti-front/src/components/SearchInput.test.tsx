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

vi.mock('../private/components/nav/useNavSearch', () => ({
  default: () => [{ path: '/dashboard/data/import', label: 'Import', parents: ['Data'] }],
}));
const mockNavigate = vi.fn();
vi.mock('react-router', async (importOriginal) => ({
  ...(await importOriginal<typeof import('react-router')>()),
  useNavigate: () => mockNavigate,
}));

describe('SearchInput (top bar) pages dropdown', () => {
  const setup = () => {
    const onSubmit = vi.fn();
    const { user } = testRender(<SearchInput variant="topBar" onSubmit={onSubmit} keyword="" />);
    return { onSubmit, user };
  };

  it('lists matching pages and a trailing "Search" row while typing', async () => {
    const { user } = setup();
    await user.type(screen.getByRole('combobox'), 'imp');

    const options = screen.getAllByRole('option');
    expect(options).toHaveLength(2);
    expect(options[0]).toHaveTextContent('Import');
    expect(options[1]).toHaveTextContent('Search: imp');
  });

  it('runs the classic search on Enter when no row is highlighted', async () => {
    const { onSubmit, user } = setup();
    await user.type(screen.getByRole('combobox'), 'imp{Enter}');

    expect(onSubmit).toHaveBeenCalledWith('imp', false, undefined);
    expect(mockNavigate).not.toHaveBeenCalled();
    expect(screen.queryAllByRole('option')).toHaveLength(0);
  });

  it('navigates to the highlighted page with the arrow keys, or searches from the last row', async () => {
    const { onSubmit, user } = setup();
    await user.type(screen.getByRole('combobox'), 'imp{ArrowDown}{Enter}');
    expect(mockNavigate).toHaveBeenCalledWith('/dashboard/data/import');
    expect(onSubmit).not.toHaveBeenCalled();

    // the first ArrowDown reopens the closed dropdown, the next two reach the last row
    await user.type(screen.getByRole('combobox'), '{ArrowDown}{ArrowDown}{ArrowDown}{Enter}');
    expect(onSubmit).toHaveBeenCalledWith('imp', false, undefined);
  });
});

describe('SearchInput (top bar)', () => {
  it('names every mode toggle, including the icon-only AI toggle', () => {
    testRender(<SearchInput variant="topBar" onSubmit={vi.fn()} keyword="" />);

    expect(screen.getByRole('button', { name: 'Advanced search' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Bulk search' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Ask AI' })).toHaveAttribute('aria-pressed', 'false');
  });
});
