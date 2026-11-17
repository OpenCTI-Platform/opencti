import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
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

  it('leaves the keys to the input method while it composes text (isComposing, and keyCode 229 as Safari sends it)', async () => {
    const { onSubmit, user } = setup();
    await user.type(screen.getByRole('combobox'), 'imp');
    const input = screen.getByRole('combobox');

    [{ isComposing: true }, { keyCode: 229 }].forEach((composition) => {
      // the arrows are not cancelled (fireEvent returns false when preventDefault was called): the IME gets them
      expect(fireEvent.keyDown(input, { key: 'ArrowDown', ...composition })).toBe(true);
      expect(input).not.toHaveAttribute('aria-activedescendant');
      // Escape only cancels the composition: it must not empty the field nor close the list
      fireEvent.keyDown(input, { key: 'Escape', ...composition });
      expect(input).toHaveValue('imp');
      expect(screen.getAllByRole('option')).toHaveLength(2);
      fireEvent.keyDown(input, { key: 'Enter', ...composition });
    });
    expect(onSubmit).not.toHaveBeenCalled();
    expect(mockNavigate).not.toHaveBeenCalled();

    // the same keys outside a composition still work
    await user.keyboard('{Enter}');
    expect(onSubmit).toHaveBeenCalledWith('imp', false, undefined);
  });

  it('navigates to the highlighted page with the arrow keys, or searches from the first row', async () => {
    const { onSubmit, user } = setup();
    // first ArrowDown highlights the "Search" row, the second the page
    await user.type(screen.getByRole('combobox'), 'imp{ArrowDown}{ArrowDown}{Enter}');
    expect(mockNavigate).toHaveBeenCalledWith('/dashboard/data/import');
    expect(onSubmit).not.toHaveBeenCalled();
    // the page is reached: the field is emptied
    expect(screen.getByRole('combobox')).toHaveValue('');

    // typing again, the first ArrowDown highlights the "Search" row
    await user.type(screen.getByRole('combobox'), 'imp{ArrowDown}{Enter}');
    expect(onSubmit).toHaveBeenCalledWith('imp', false, undefined);
    // a classic search keeps its keyword visible
    expect(screen.getByRole('combobox')).toHaveValue('imp');
  });

  it('empties the field when a page row is clicked', async () => {
    const { user } = setup();
    await user.type(screen.getByRole('combobox'), 'imp');
    await user.click(screen.getByRole('option', { name: /Import/ }));

    expect(screen.getByRole('combobox')).toHaveValue('');
  });
});

describe('SearchInput (top bar) pages only', () => {
  const setup = () => {
    const onSubmit = vi.fn();
    const { user } = testRender(<SearchInput variant="topBar" pagesOnly onSubmit={onSubmit} keyword="" />);
    return { onSubmit, user };
  };

  it('offers no classic, bulk nor AI search, and lists only the pages', async () => {
    const { user } = setup();
    expect(screen.queryByRole('button', { name: 'Advanced search' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Bulk search' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Ask AI' })).not.toBeInTheDocument();

    await user.type(screen.getByRole('combobox'), 'imp');
    const options = screen.getAllByRole('option');
    expect(options).toHaveLength(1);
    expect(options[0]).toHaveTextContent('Import');
  });

  it('does nothing on Enter when no page is highlighted', async () => {
    const { onSubmit, user } = setup();
    await user.type(screen.getByRole('combobox'), 'imp{Enter}');

    expect(onSubmit).not.toHaveBeenCalled();
    expect(mockNavigate).not.toHaveBeenCalled();
  });

  it('navigates to the page highlighted with the arrow keys, which start at the first page', async () => {
    const { onSubmit, user } = setup();
    await user.type(screen.getByRole('combobox'), 'imp{ArrowDown}');
    expect(screen.getByRole('combobox')).toHaveAttribute('aria-activedescendant', 'nav-search-suggestions-option-0');

    await user.type(screen.getByRole('combobox'), '{Enter}');
    expect(mockNavigate).toHaveBeenCalledWith('/dashboard/data/import');
    expect(onSubmit).not.toHaveBeenCalled();
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
