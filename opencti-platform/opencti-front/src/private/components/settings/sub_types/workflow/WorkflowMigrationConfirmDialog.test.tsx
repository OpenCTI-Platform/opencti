import { Suspense } from 'react';
import { screen, waitFor } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import { describe, expect, it, vi } from 'vitest';
import testRender from '../../../../../utils/tests/test-render';
import { StatusScopeEnum } from '../../../../../utils/statusConstants';
import WorkflowMigrationConfirmDialog from './WorkflowMigrationConfirmDialog';

const renderDialog = (props: Partial<Parameters<typeof WorkflowMigrationConfirmDialog>[0]> = {}) => {
  const onConfirm = vi.fn();
  const onCancel = vi.fn();
  const onNoLegacyData = vi.fn();
  const utils = testRender(
    <Suspense fallback={<div>loading</div>}>
      <WorkflowMigrationConfirmDialog
        entityType="Report"
        scope={StatusScopeEnum.GLOBAL}
        onConfirm={onConfirm}
        onCancel={onCancel}
        onNoLegacyData={onNoLegacyData}
        {...props}
      />
    </Suspense>,
  );
  return {
    ...utils, onConfirm, onCancel, onNoLegacyData,
  };
};

describe('WorkflowMigrationConfirmDialog', () => {
  it('renders the diagnostics for the matching scope and does not call the migration mutation until confirmed', async () => {
    const { relayEnv, user, onConfirm } = renderDialog();

    await waitFor(() => {
      relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
        WorkflowMigrationPreview: () => ({
          entityType: 'Report',
          results: [
            {
              scope: 'REQUEST_ACCESS',
              diagnostics: [{ type: 'other_scope', message: 'Should not be shown', statusId: null }],
            },
            {
              scope: 'GLOBAL',
              diagnostics: [{ type: 'ambiguous_order', message: 'Two statuses share the same order', statusId: 'status-1' }],
            },
          ],
        }),
      }));
    });

    expect(await screen.findByText('Two statuses share the same order')).toBeInTheDocument();
    expect(screen.queryByText('Should not be shown')).not.toBeInTheDocument();

    // The preview query has already resolved and the migration mutation must not fire on render.
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
    expect(onConfirm).not.toHaveBeenCalled();

    await user.click(screen.getByText('Confirm'));

    await waitFor(() => {
      const migrateOperation = relayEnv.mock.getAllOperations()
        .find((op) => op.request.node.params.name === 'WorkflowMigrationConfirmDialogMutation');
      expect(migrateOperation).toBeDefined();
      expect(migrateOperation?.request.variables).toEqual({ entityType: 'Report', scope: 'GLOBAL' });
    });

    expect(onConfirm).not.toHaveBeenCalled();

    await waitFor(() => {
      relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
        MigrateEntityTypeStatusResult: () => ({ entityType: 'Report', status: 'migrated' }),
      }));
    });

    await waitFor(() => expect(onConfirm).toHaveBeenCalledOnce());
  });

  it('calls onCancel and does not call the migration mutation when Cancel is clicked', async () => {
    const { relayEnv, user, onCancel } = renderDialog();

    await waitFor(() => {
      relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
        WorkflowMigrationPreview: () => ({
          entityType: 'Report',
          results: [{ scope: 'GLOBAL', diagnostics: [] }],
        }),
      }));
    });

    await user.click(await screen.findByText('Cancel'));

    expect(onCancel).toHaveBeenCalledOnce();
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
  });

  it('calls onNoLegacyData and renders nothing when the preview has no results for the current scope', async () => {
    const { relayEnv, onNoLegacyData, onConfirm, onCancel } = renderDialog();

    await waitFor(() => {
      relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
        WorkflowMigrationPreview: () => ({
          entityType: 'Report',
          results: [
            {
              scope: 'REQUEST_ACCESS',
              diagnostics: [{ type: 'other_scope', message: 'Not relevant here', statusId: null }],
            },
          ],
        }),
      }));
    });

    await waitFor(() => expect(onNoLegacyData).toHaveBeenCalledOnce());

    expect(screen.queryByText('Confirm')).not.toBeInTheDocument();
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
    expect(onConfirm).not.toHaveBeenCalled();
    expect(onCancel).not.toHaveBeenCalled();
  });
});
