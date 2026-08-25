import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { DialogActions, List, ListItem, ListItemText } from '@mui/material';
import { FunctionComponent, useEffect } from 'react';
import { graphql, useLazyLoadQuery, useMutation } from 'react-relay';
import { useFormatter } from '../../../../../components/i18n';
import { MESSAGING$ } from '../../../../../relay/environment';
import { StatusScopeEnum } from '../../../../../utils/statusConstants';
import type { WorkflowMigrationConfirmDialogMutation as WorkflowMigrationConfirmDialogMutationType } from './__generated__/WorkflowMigrationConfirmDialogMutation.graphql';
import type { WorkflowMigrationConfirmDialogQuery as WorkflowMigrationConfirmDialogQueryType } from './__generated__/WorkflowMigrationConfirmDialogQuery.graphql';

export const workflowMigrationPreviewQuery = graphql`
  query WorkflowMigrationConfirmDialogQuery($entityType: String!) {
    workflowMigrationPreview(entityType: $entityType) {
      results {
        scope
        diagnostics {
          type
          message
          statusId
        }
      }
    }
  }
`;

const workflowMigrationConfirmDialogMutation = graphql`
  mutation WorkflowMigrationConfirmDialogMutation($entityType: String!, $scope: StatusScope!) {
    migrateEntityTypeStatusToWorkflowDefinition(entityType: $entityType, scope: $scope) {
      entityType
      status
    }
  }
`;

interface WorkflowMigrationConfirmDialogProps {
  entityType: string;
  scope: StatusScopeEnum;
  onConfirm: () => void;
  onCancel: () => void;
  // Called instead of rendering the dialog when the preview has no legacy `Status` data for
  // `scope` (brand-new entity type, or already migrated) — lets the caller fall through to the
  // graph editor unchanged, without a spurious confirm prompt.
  onNoLegacyData: () => void;
}

// Task 6: gates entry to the graph editor when the entity type still has un-migrated legacy
// `Status` data for the current scope — see workflowMigrationPreview (Task 5). One
// WorkflowMigrationScopeResult is returned per scope present in the legacy data, so we must
// select the entry matching the current `scope`, not assume `results[0]`.
const WorkflowMigrationConfirmDialog: FunctionComponent<WorkflowMigrationConfirmDialogProps> = ({
  entityType,
  scope,
  onConfirm,
  onCancel,
  onNoLegacyData,
}) => {
  const { t_i18n } = useFormatter();

  const data = useLazyLoadQuery<WorkflowMigrationConfirmDialogQueryType>(
    workflowMigrationPreviewQuery,
    { entityType },
    { fetchPolicy: 'network-only' },
  );
  const scopeResult = data.workflowMigrationPreview?.results.find((result) => result.scope === scope);
  const hasLegacyData = !!scopeResult;
  const diagnostics = scopeResult?.diagnostics ?? [];

  const [commitMigrate, isMigrating] = useMutation<WorkflowMigrationConfirmDialogMutationType>(
    workflowMigrationConfirmDialogMutation,
  );

  useEffect(() => {
    if (!hasLegacyData) {
      onNoLegacyData();
    }
  }, [hasLegacyData]);

  if (!hasLegacyData) {
    return null;
  }

  const handleConfirm = () => {
    commitMigrate({
      variables: { entityType, scope },
      onCompleted: () => {
        MESSAGING$.notifySuccess(t_i18n('Existing statuses successfully migrated to a workflow'));
        onConfirm();
      },
      onError: () => {
        MESSAGING$.notifyError(t_i18n('An error occurred while migrating existing statuses to a workflow'));
      },
    });
  };

  return (
    <Dialog
      open
      onClose={onCancel}
      title={t_i18n('Migrate existing statuses to a workflow')}
      size="small"
    >
      {t_i18n('This entity type currently uses legacy statuses. Continuing will convert them into an editable workflow.')}
      {diagnostics.length > 0 && (
        <List dense>
          {diagnostics.map((diagnostic, index) => (
            <ListItem key={`${diagnostic.type}-${index}`} disableGutters>
              <ListItemText primary={diagnostic.message} />
            </ListItem>
          ))}
        </List>
      )}
      <DialogActions>
        <Button variant="secondary" onClick={onCancel}>
          {t_i18n('Cancel')}
        </Button>
        <Button onClick={handleConfirm} disabled={isMigrating}>
          {t_i18n('Confirm')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default WorkflowMigrationConfirmDialog;
