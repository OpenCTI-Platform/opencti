import React from 'react';
import { act, fireEvent, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import { KNOWLEDGE } from '../../../utils/hooks/useGranted';
import { writeSearchShortcut } from '../../../utils/hooks/useSearchShortcut';
import TopBar from './TopBar';

vi.mock('../../../components/UploadImport', () => ({ default: () => null }));
vi.mock('../../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../relay/environment')>()),
  requestSubscription: () => ({ dispose: () => undefined }),
}));
// Only what TopBar hands to the field matters here
vi.mock('../../../components/SearchInput', () => ({
  default: ({ placeholder, id, ...props }: { placeholder: string; id: string }) => (
    <input id={id} placeholder={placeholder} aria-keyshortcuts={props['aria-keyshortcuts' as keyof typeof props]} />
  ),
}));
vi.mock('use-analytics', () => ({ usePage: () => vi.fn() }));
vi.mock('../chatbox/AskArianeButton', () => ({ default: () => null }));
vi.mock('../chatbox/CtemCommandCenterButton', () => ({ default: () => null }));
vi.mock('../cases/feedbacks/FeedbackCreation', () => ({ default: () => null }));
vi.mock('../common/ai/AINLQ', () => ({ useAINLQ: () => ({ search: vi.fn(), isLoading: false }) }));

const renderTopBar = async () => {
  const result = testRender(<TopBar />, {
    userContext: createMockUserContext({
      me: { id: 'user-id', capabilities: [{ name: KNOWLEDGE }], capabilitiesInDraft: [], draftContext: null },
      settings: { platform_enterprise_edition: { license_type: 'standard' } },
    }),
  });
  await act(async () => {
    result.relayEnv.mock.resolveMostRecentOperation({ data: { myUnreadNotificationsCount: 0, myUnreadNewsFeedsCount: 0 } });
  });
  return result;
};

describe('TopBar search shortcut', () => {
  afterEach(() => localStorage.clear());

  it('shows the shortcut in the empty search field, and focuses the field when pressed', async () => {
    await renderTopBar();
    const field = screen.getByPlaceholderText('Type / to search');
    expect(field).toHaveAttribute('aria-keyshortcuts', '/');

    fireEvent.keyDown(document.body, { key: '/' });
    expect(field).toHaveFocus();
  });

  it('shows the shortcut chosen by the user, and nothing once it is turned off', async () => {
    await renderTopBar();
    act(() => writeSearchShortcut({ key: 'k', ctrl: true, meta: false, shift: false }));
    expect(screen.getByPlaceholderText('Type Ctrl+K to search')).toHaveAttribute('aria-keyshortcuts', 'Control+K');

    act(() => writeSearchShortcut(null));
    expect(screen.getByPlaceholderText('Search')).not.toHaveAttribute('aria-keyshortcuts');
  });
});
