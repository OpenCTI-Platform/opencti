import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import UserCreation from './UserCreation';

// The default groups are read from a preloaded query: only their names are displayed by this form.
vi.mock('react-relay', async (importOriginal) => ({
  ...(await importOriginal<typeof import('react-relay')>()),
  usePreloadedQuery: () => ({ groups: { edges: [] } }),
}));
// Fields backed by their own queries or fragments are out of the scope of this test.
vi.mock('../../common/form/GroupField', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../common/form/GroupField')>()),
  default: () => null,
}));
vi.mock('../../common/form/ObjectOrganizationField', () => ({ default: () => null }));
vi.mock('../../common/form/EmailTemplateField', () => ({ default: () => null }));
vi.mock('../../common/form/PasswordPolicies', () => ({ default: () => <div>Password policies</div> }));
vi.mock('./edition/UserConfidenceLevelField', () => ({ default: () => null }));

const userContext = createMockUserContext({
  me: { name: 'admin', capabilities: [{ name: 'BYPASS' }], userSubscriptions: { edges: [] } },
  settings: { platform_user_statuses: [{ status: 'Active' }] },
});

const renderOpenDrawer = async () => {
  const rendered = testRender(
    <UserCreation paginationOptions={{}} defaultGroupsQueryRef={{}} />,
    { userContext },
  );
  await rendered.user.click(screen.getByTestId('create-user-button'));
  await screen.findByTestId('user-creation-password-input');
  return rendered;
};

describe('UserCreation', () => {
  it('asks for a password when creating a regular user', async () => {
    await renderOpenDrawer();
    expect(screen.getByText('Password policies')).toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toBeInTheDocument();
    expect(screen.getByLabelText('Confirmation')).toBeInTheDocument();
  });

  it('does not ask for a password when creating a service account', async () => {
    const { user } = await renderOpenDrawer();
    await user.click(screen.getByRole('switch', { name: 'This user is a service account' }));
    expect(screen.queryByText('Password policies')).not.toBeInTheDocument();
    expect(screen.queryByTestId('user-creation-password-input')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Confirmation')).not.toBeInTheDocument();
  });

  it('clears a password typed before switching to a service account', async () => {
    const { user } = await renderOpenDrawer();
    await user.type(screen.getByLabelText('Password'), 'secret');
    await user.type(screen.getByLabelText('Confirmation'), 'other');
    const serviceAccountSwitch = screen.getByRole('switch', { name: 'This user is a service account' });
    await user.click(serviceAccountSwitch);
    await user.click(serviceAccountSwitch);
    expect(screen.getByLabelText('Password')).toHaveValue('');
    expect(screen.getByLabelText('Confirmation')).toHaveValue('');
  });
});
