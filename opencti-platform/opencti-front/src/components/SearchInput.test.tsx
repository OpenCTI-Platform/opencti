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
  PLATFORM_SEARCH_PAGE_MAX_RESULTS: 10,
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

  it('lists a leading "Search" row then the matching pages while typing', async () => {
    const { user } = setup();
    await user.type(screen.getByRole('combobox'), 'imp');

    const options = screen.getAllByRole('option');
    expect(options).toHaveLength(2);
    expect(options[0]).toHaveTextContent('Search: imp');
    expect(options[1]).toHaveTextContent('Import');
  });

  it('waits for two characters before listing pages, Enter still runs the classic search', async () => {
    const { onSubmit, user } = setup();
    await user.type(screen.getByRole('combobox'), 'i');
    expect(screen.queryAllByRole('option')).toHaveLength(0);

    await user.type(screen.getByRole('combobox'), '{Enter}');
    expect(onSubmit).toHaveBeenCalledWith('i', false, undefined);
  });

  it('names the list and keeps the rows out of the tab order (focus stays in the input)', async () => {
    const { user } = setup();
    await user.type(screen.getByRole('combobox'), 'imp');

    expect(screen.getByRole('listbox', { name: 'Suggestions' })).toBeInTheDocument();
    screen.getAllByRole('option').forEach((option) => expect(option).toHaveAttribute('tabindex', '-1'));
  });

  it('renders page rows as real links (new tab works) and closes the list on click', async () => {
    const { user } = setup();
    await user.type(screen.getByRole('combobox'), 'imp');

    const page = screen.getByRole('option', { name: /Import/ });
    expect(page).toHaveAttribute('href', '/dashboard/data/import');
    await user.click(page);
    expect(screen.queryAllByRole('option')).toHaveLength(0);
  });

  it('runs the classic search on Enter when no row is highlighted', async () => {
    const { onSubmit, user } = setup();
    await user.type(screen.getByRole('combobox'), 'imp{Enter}');

    expect(onSubmit).toHaveBeenCalledWith('imp', false, undefined);
    expect(mockNavigate).not.toHaveBeenCalled();
    expect(screen.queryAllByRole('option')).toHaveLength(0);
  });

  it('navigates to the highlighted page with the arrow keys, or searches from the first row', async () => {
    const { onSubmit, user } = setup();
    // first ArrowDown highlights the "Search" row, the second the page
    await user.type(screen.getByRole('combobox'), 'imp{ArrowDown}{ArrowDown}{Enter}');
    expect(mockNavigate).toHaveBeenCalledWith('/dashboard/data/import');
    expect(onSubmit).not.toHaveBeenCalled();

    // the first ArrowDown reopens the closed dropdown, the next one highlights the "Search" row
    await user.type(screen.getByRole('combobox'), '{ArrowDown}{ArrowDown}{Enter}');
    expect(onSubmit).toHaveBeenCalledWith('imp', false, undefined);
  });
});

describe('SearchInput (top bar) shortcut target', () => {
  it('puts the id and the announced shortcut on the input itself', () => {
    testRender(<SearchInput variant="topBar" onSubmit={vi.fn()} keyword="" id="top-bar-search" aria-keyshortcuts="/" />);

    expect(screen.getByRole('combobox')).toHaveAttribute('id', 'top-bar-search');
    expect(screen.getByRole('combobox')).toHaveAttribute('aria-keyshortcuts', '/');
  });
});

describe('SearchInput (top bar) in bulk mode', () => {
  it('is not announced as a combobox and shows no pages dropdown', async () => {
    const { user } = testRender(<SearchInput variant="topBar" onSubmit={vi.fn()} keyword="" />);
    await user.click(screen.getByRole('button', { name: 'Bulk search' }));

    expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
    await user.type(document.querySelector('input[name="keyword"]') as HTMLInputElement, 'imp');
    expect(screen.queryAllByRole('option')).toHaveLength(0);
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
