import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import UserEdition from './UserEdition';
import { RootUserEditionQuery$data } from './__generated__/RootUserEditionQuery.graphql';

// The fragment reference is given already resolved: only the tabs of the drawer are under test.
vi.mock('react-relay', async (importOriginal) => ({
  ...(await importOriginal<typeof import('react-relay')>()),
  useFragment: (_: unknown, ref: unknown) => ref,
}));
vi.mock('./edition/UserEditionOverview', () => ({ default: () => null }));
vi.mock('./edition/UserEditionPassword', () => ({ default: () => null }));
vi.mock('./edition/UserEditionGroups', () => ({ default: () => null }));
vi.mock('./edition/UserEditionOrganizationsAdmin', () => ({ default: () => null }));
vi.mock('./edition/UserEditionConfidence', () => ({ default: () => null }));
vi.mock('./edition/UserEditionDeduplication', () => ({ default: () => null }));

const userContext = createMockUserContext({
  me: { name: 'admin', capabilities: [{ name: 'BYPASS' }], userSubscriptions: { edges: [] } },
});

const renderDrawer = (user: Record<string, unknown>) => testRender(
  <UserEdition
    open
    userEditionData={{
      user: {
        id: 'user-id',
        external: false,
        user_service_account: false,
        editContext: null,
        objectAssignedOrganization: { edges: [] },
        ...user,
      },
    } as unknown as RootUserEditionQuery$data}
  />,
  { userContext },
);

describe('UserEdition', () => {
  it('offers the password tab for a regular user', async () => {
    renderDrawer({});
    expect(await screen.findByRole('tab', { name: 'Password' })).toBeEnabled();
  });

  it('keeps the password tab disabled for an external user', async () => {
    renderDrawer({ external: true });
    expect(await screen.findByRole('tab', { name: 'Password' })).toBeDisabled();
  });

  it('does not offer the password tab for a service account', async () => {
    renderDrawer({ user_service_account: true });
    expect(await screen.findByRole('tab', { name: 'Overview' })).toBeInTheDocument();
    expect(screen.queryByRole('tab', { name: 'Password' })).not.toBeInTheDocument();
  });
});
