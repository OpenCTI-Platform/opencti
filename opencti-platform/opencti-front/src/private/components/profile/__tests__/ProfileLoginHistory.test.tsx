import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import ProfileLoginHistory from '../ProfileLoginHistory';
import { ProfileLoginHistory_me$key } from '../__generated__/ProfileLoginHistory_me.graphql';

const flags = vi.hoisted(() => ({ enterpriseEdition: true }));

vi.mock('react-relay', async (importOriginal) => ({
  ...(await importOriginal<typeof import('react-relay')>()),
  useFragment: (_: unknown, ref: unknown) => ref,
}));
vi.mock('../../../../utils/hooks/useEnterpriseEdition', () => ({
  default: () => flags.enterpriseEdition,
}));

const me = (loginHistory: { id: string; timestamp: string; provider: string | null }[]) => ({
  login_history: loginHistory,
}) as unknown as ProfileLoginHistory_me$key;

const LOGINS = [
  { id: 'log-2', timestamp: '2026-11-25T10:00:00.000Z', provider: 'local' },
  { id: 'log-1', timestamp: '2026-11-24T08:30:00.000Z', provider: null },
];

describe('ProfileLoginHistory', () => {
  beforeEach(() => {
    flags.enterpriseEdition = true;
  });

  it('lists the last logins with their provider', () => {
    testRender(<ProfileLoginHistory me={me(LOGINS)} loginHistoryCount={5} />);
    expect(screen.getByText('Last logins')).toBeInTheDocument();
    expect(screen.getAllByRole('row')).toHaveLength(3); // The header and the two logins
    expect(screen.getByText('local')).toBeInTheDocument();
    expect(screen.getByText('-')).toBeInTheDocument();
  });

  it('says when no login is recorded yet', () => {
    testRender(<ProfileLoginHistory me={me([])} loginHistoryCount={5} />);
    expect(screen.getByText('No login recorded yet.')).toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });

  it('is hidden when the count is 0 or without Enterprise Edition', () => {
    const { unmount } = testRender(<ProfileLoginHistory me={me(LOGINS)} loginHistoryCount={0} />);
    expect(screen.queryByText('Last logins')).not.toBeInTheDocument();
    unmount();
    flags.enterpriseEdition = false;
    testRender(<ProfileLoginHistory me={me(LOGINS)} loginHistoryCount={5} />);
    expect(screen.queryByText('Last logins')).not.toBeInTheDocument();
  });
});
