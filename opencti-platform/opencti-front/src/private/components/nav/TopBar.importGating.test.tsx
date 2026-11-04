import React from 'react';
import { act, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import { KNOWLEDGE, KNOWLEDGE_KNASKIMPORT, KNOWLEDGE_KNFORMINTAKE, KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import TopBar from './TopBar';

vi.mock('../../../components/UploadImport', () => ({ default: () => <button type="button">Import data</button> }));
vi.mock('../../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../relay/environment')>()),
  requestSubscription: () => ({ dispose: () => undefined }),
}));
vi.mock('../../../components/SearchInput', () => ({ default: () => null }));
vi.mock('use-analytics', () => ({ usePage: () => vi.fn() }));
vi.mock('../chatbox/AskArianeButton', () => ({ default: () => null }));
vi.mock('../chatbox/CtemCommandCenterButton', () => ({ default: () => null }));
vi.mock('../cases/feedbacks/FeedbackCreation', () => ({ default: () => null }));
vi.mock('../common/ai/AINLQ', () => ({ useAINLQ: () => ({ search: vi.fn(), isLoading: false }) }));

const renderTopBar = async (capabilities: string[], capabilitiesInDraft: string[] = []) => {
  const result = testRender(<TopBar />, {
    userContext: createMockUserContext({
      me: {
        id: 'user-id',
        capabilities: capabilities.map((name) => ({ name })),
        capabilitiesInDraft: capabilitiesInDraft.map((name) => ({ name })),
        draftContext: null,
      },
      settings: { platform_enterprise_edition: { license_type: 'standard' } },
    }),
  });
  await act(async () => {
    result.relayEnv.mock.resolveMostRecentOperation({ data: { myUnreadNotificationsCount: 0, myUnreadNewsFeedsCount: 0 } });
  });
  return result;
};

describe('TopBar import button gating', () => {
  it('shows the import button to a form-only user (KNFORMINTAKE)', async () => {
    await renderTopBar([KNOWLEDGE, KNOWLEDGE_KNFORMINTAKE]);
    expect(screen.getByRole('button', { name: 'Import data' })).toBeInTheDocument();
  });

  it('keeps showing the import button to a user with KNASKIMPORT', async () => {
    await renderTopBar([KNOWLEDGE, KNOWLEDGE_KNASKIMPORT]);
    expect(screen.getByRole('button', { name: 'Import data' })).toBeInTheDocument();
  });

  it('hides the import button from a user with neither KNASKIMPORT nor KNFORMINTAKE', async () => {
    await renderTopBar([KNOWLEDGE, KNOWLEDGE_KNUPDATE]);
    expect(screen.queryByRole('button', { name: 'Import data' })).not.toBeInTheDocument();
  });
});
