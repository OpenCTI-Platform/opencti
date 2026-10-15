import React from 'react';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import StixDomainObjectHeader from './StixDomainObjectHeader';

const mocks = vi.hoisted(() => ({
  commitMutation: vi.fn(),
  enforceReferences: false,
}));

vi.mock('react-relay', async (importOriginal) => ({
  ...(await importOriginal<typeof import('react-relay')>()),
  graphql: (query: TemplateStringsArray) => query,
  useLazyLoadQuery: () => ({}),
}));

vi.mock('../../../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../relay/environment')>()),
  commitMutation: mocks.commitMutation,
}));

vi.mock('../../../../utils/hooks/useEntitySettings', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../utils/hooks/useEntitySettings')>()),
  useIsEnforceReference: () => mocks.enforceReferences,
}));

vi.mock('../../../../utils/hooks/useGranted', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../utils/hooks/useGranted')>()),
  default: () => true,
}));

vi.mock('../../../../utils/Security', async (importOriginal) => {
  const Passthrough = ({ children }: { children: React.ReactNode }) => <>{children}</>;
  return {
    ...(await importOriginal<typeof import('../../../../utils/Security')>()),
    default: Passthrough,
    CollaborativeSecurity: Passthrough,
  };
});

// Unrelated header parts with their own queries.
vi.mock('../stix_core_objects/StixCoreObjectSharingList', () => ({ default: () => null }));
vi.mock('../stix_core_objects/StixCoreObjectQuickSubscription', () => ({ default: () => null }));
vi.mock('../stix_core_objects/StixCoreObjectFileExport', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../stix_core_objects/StixCoreObjectFileExport')>()),
  default: () => null,
}));
vi.mock('../stix_core_objects/StixCoreObjectFileExportButton', () => ({ default: () => null }));
vi.mock('../stix_core_objects/StixCoreObjectEnrichment', () => ({ default: () => null }));
vi.mock('../stix_core_objects/StixCoreObjectEnrollPlaybook', () => ({ default: () => null }));
vi.mock('../stix_core_objects/StixCoreObjectSharing', () => ({ default: () => null }));
vi.mock('../stix_core_objects/StixCoreObjectContainer', () => ({ default: () => null }));
vi.mock('../form/FormAuthorizedMembersDialog', () => ({ default: () => null }));
vi.mock('../form/CommitMessage', () => ({
  default: ({ open }: { open: boolean }) => (open ? <div data-testid="commit-message" /> : null),
}));

const stixDomainObject = {
  id: 'intrusion-set-1',
  entity_type: 'Intrusion-Set',
  name: 'APT 1',
  aliases: ['Comment Crew'],
  currentUserAccessRight: 'admin',
};

const renderHeader = () => testRender(
  <StixDomainObjectHeader stixDomainObject={stixDomainObject} entityType="Intrusion-Set" DeleteComponent={() => null} />,
);

const openAliasesDialog = async (user: ReturnType<typeof testRender>['user']) => {
  await user.click(screen.getByRole('button', { name: 'Alias' }));
  return screen.findByRole('dialog', { name: 'Entity aliases' });
};

describe('StixDomainObjectHeader aliases dialog', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.enforceReferences = false;
  });

  it('focuses the new alias field once the dialog has opened', async () => {
    const { user } = renderHeader();
    const dialog = await openAliasesDialog(user);
    await waitFor(() => expect(within(dialog).getByLabelText('New alias')).toHaveFocus());
  });

  it('adds the typed alias with the Add button', async () => {
    const { user } = renderHeader();
    const dialog = await openAliasesDialog(user);

    await user.type(within(dialog).getByLabelText('New alias'), 'APT-1 bis');
    await user.click(within(dialog).getByRole('button', { name: 'Add' }));

    await waitFor(() => expect(mocks.commitMutation).toHaveBeenCalledOnce());
    expect(mocks.commitMutation.mock.calls[0][0].variables.input).toEqual({ key: 'aliases', value: ['Comment Crew', 'APT-1 bis'] });
  });

  it('adds the typed alias with Enter, once', async () => {
    const { user } = renderHeader();
    const dialog = await openAliasesDialog(user);

    await user.type(within(dialog).getByLabelText('New alias'), 'APT-1 bis{Enter}');

    await waitFor(() => expect(mocks.commitMutation).toHaveBeenCalledOnce());
  });

  it('adds nothing when the field is empty', async () => {
    const { user } = renderHeader();
    const dialog = await openAliasesDialog(user);

    await user.click(within(dialog).getByRole('button', { name: 'Add' }));

    expect(mocks.commitMutation).not.toHaveBeenCalled();
  });

  it('asks for references before adding when they are enforced', async () => {
    mocks.enforceReferences = true;
    const { user } = renderHeader();
    const dialog = await openAliasesDialog(user);

    await user.type(within(dialog).getByLabelText('New alias'), 'APT-1 bis');
    await user.click(within(dialog).getByRole('button', { name: 'Add' }));

    // Exactly one: an unused hidden create form used to open a second one.
    await waitFor(() => expect(screen.getAllByTestId('commit-message')).toHaveLength(1));
    expect(mocks.commitMutation).not.toHaveBeenCalled();
  });
});
