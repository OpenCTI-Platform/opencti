import React from 'react';
import { act, screen } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import { describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import XtmHubSettings from './XtmHubSettings';

// Loader has no accessible markup: expose each variant so the tests can tell
// the card-level spinner from the page-level one.
vi.mock('../../../../components/Loader', () => ({
  LoaderVariant: { container: 'container', inElement: 'inElement', inline: 'inline' },
  default: ({ variant }: { variant?: string }) => <div data-testid={`loader-${variant ?? 'container'}`} />,
}));

// XtmHubTab drives dialogs and external windows, irrelevant here.
vi.mock('./XtmHubTab', () => ({ default: () => null }));

const userContext = createMockUserContext({
  me: { capabilities: [{ name: 'BYPASS' }] },
  settings: { platform_xtmhub_url: 'https://hub.example.com' },
});

// Same shape as the Experience page: a page-level Suspense wrapping the
// sibling content (the Enterprise Edition card) and the XTM Hub card.
const renderExperienceLikePage = () => testRender(
  <React.Suspense fallback={<div data-testid="page-loader" />}>
    <div data-testid="enterprise-edition-card">Enterprise Edition</div>
    <XtmHubSettings />
  </React.Suspense>,
  { userContext },
);

describe('XtmHubSettings', () => {
  it('keeps the rest of the page visible while its settings query is loading', async () => {
    const { relayEnv } = renderExperienceLikePage();

    // 1. Connectivity check is in flight: card-level spinner only.
    expect(relayEnv.mock.getMostRecentOperation().fragment.node.name).toBe('XtmHubSettingsCheckConnectivityMutation');
    expect(screen.getByTestId('loader-inElement')).toBeInTheDocument();
    expect(screen.getByTestId('enterprise-edition-card')).toBeVisible();

    // 2. Check completes: XtmHubSettingsComponent mounts and suspends on its
    //    network-only query. The page must not be replaced by the page loader.
    await act(async () => {
      relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation));
    });
    expect(relayEnv.mock.getMostRecentOperation().fragment.node.name).toBe('XtmHubSettingsQuery');
    expect(screen.queryByTestId('page-loader')).not.toBeInTheDocument();
    expect(screen.getByTestId('enterprise-edition-card')).toBeVisible();
    expect(screen.getByTestId('loader-inElement')).toBeInTheDocument();
    expect(screen.queryByTestId('experience-xtm-hub-card')).not.toBeInTheDocument();

    // 3. Query resolves: the card replaces its spinner, the page never blinked.
    await act(async () => {
      relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
        Settings: () => ({
          id: 'settings-id',
          xtm_hub_registration_status: 'unregistered',
          xtm_hub_backend_is_reachable: true,
        }),
      }));
    });
    expect(await screen.findByTestId('experience-xtm-hub-card')).toBeInTheDocument();
    expect(screen.queryByTestId('loader-inElement')).not.toBeInTheDocument();
    expect(screen.queryByTestId('page-loader')).not.toBeInTheDocument();
    expect(screen.getByTestId('enterprise-edition-card')).toBeVisible();
  });
});
