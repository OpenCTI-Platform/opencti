import React, { useReducer } from 'react';
import { act, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ChatPanelProps } from '@filigran/chatbot';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import AskArianePanel from './AskArianePanel';

const { chatPanelRenders } = vi.hoisted(() => ({ chatPanelRenders: [] as ChatPanelProps[] }));

vi.mock('@filigran/chatbot', () => ({
  ChatPanel: (props: ChatPanelProps) => {
    chatPanelRenders.push(props);
    return null;
  },
}));

// The banners only offset the panel vertically.
vi.mock('../../../utils/hooks/useTopBanner', () => ({
  default: () => ({ height: 0 }),
}));
vi.mock('../settings/settings_messages/SettingsMessagesBanner', () => ({
  useSettingsMessagesBannerHeight: () => 0,
}));

// Every object and callback the panel builds for `ChatPanel`.
const IDENTITY_PROPS: (keyof ChatPanelProps)[] = [
  'apiEndpoints',
  'user',
  'logoIcon',
  'promptSuggestions',
  'requestHeaders',
  'pageContext',
  'onRelativeLinkClick',
  'onTaskComplete',
  't',
];

let rerenderHost = () => {};

// Re-renders the panel the way `AskArianeButton` does on every chatbot
// context change (a sidebar resize step, for instance), providers untouched.
const Host = () => {
  const [, forceRender] = useReducer((count: number) => count + 1, 0);
  rerenderHost = forceRender;
  return (
    <AskArianePanel
      mode="sidebar"
      onClose={() => {}}
      onModeChange={() => {}}
      onResizeStart={() => {}}
      onResizeEnd={() => {}}
    />
  );
};

const lastChatPanelProps = () => chatPanelRenders[chatPanelRenders.length - 1];

const renderPanel = async (me?: unknown) => {
  testRender(<Host />, {
    route: '/dashboard',
    userContext: createMockUserContext({ me, bannerSettings: { bannerHeightNumber: 0 } }),
  });
  await waitFor(() => expect(chatPanelRenders.length).toBeGreaterThan(0));
  return lastChatPanelProps();
};

describe('AskArianePanel', () => {
  beforeEach(() => {
    chatPanelRenders.length = 0;
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({ ok: false })));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('hands the chat panel the same objects and callbacks when it re-renders', async () => {
    const first = await renderPanel();
    const rendersBefore = chatPanelRenders.length;

    act(() => rerenderHost());

    expect(chatPanelRenders.length).toBeGreaterThan(rendersBefore);
    const second = lastChatPanelProps();
    IDENTITY_PROPS.forEach((prop) => expect(second[prop], prop).toBe(first[prop]));
  });

  it('keeps the draft header object while a draft is active', async () => {
    const first = await renderPanel({ user_email: 'jane@opencti.io', draftContext: { id: 'draft-1' } });
    expect(first.requestHeaders).toEqual({ 'opencti-draft-id': 'draft-1' });

    act(() => rerenderHost());

    expect(lastChatPanelProps().requestHeaders).toBe(first.requestHeaders);
  });

  it('keeps the link handler across the route change it triggers', async () => {
    const first = await renderPanel();
    expect(first.pageContext).toEqual({ url: '/dashboard' });

    act(() => first.onRelativeLinkClick?.('/dashboard/analyses/reports'));

    await waitFor(() => expect(lastChatPanelProps().pageContext).toEqual({ url: '/dashboard/analyses/reports' }));
    const afterNavigation = lastChatPanelProps();
    IDENTITY_PROPS
      .filter((prop) => prop !== 'pageContext')
      .forEach((prop) => expect(afterNavigation[prop], prop).toBe(first[prop]));
  });
});
