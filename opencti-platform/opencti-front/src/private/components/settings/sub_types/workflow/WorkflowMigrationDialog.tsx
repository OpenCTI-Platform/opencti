import { Suspense, useState } from 'react';
import { DialogActions } from '@mui/material';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { Alert, Checkbox, Chip, Switch, Text } from '@filigran/design-system';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { ErrorBoundary } from '../../../Error';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import { useFormatter } from '../../../../../components/i18n';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import RequestAccessOutcomeRepair from './RequestAccessOutcomeRepair';
import type { WorkflowScope } from '../SubTypeWorkflow';
import { WorkflowMigrationDialogPreviewQuery } from './__generated__/WorkflowMigrationDialogPreviewQuery.graphql';
import { WorkflowMigrationDialogMutation } from './__generated__/WorkflowMigrationDialogMutation.graphql';

export const workflowMigrationPreviewQuery = graphql`
  query WorkflowMigrationDialogPreviewQuery($entityType: String!) {
    workflowMigrationPreview(entityType: $entityType) {
      entityType
      results {
        scope
        initialState
        hasPublishedVersion
        states {
          statusId
          order
          requestAccessOutcome
        }
        transitions {
          event
          from
          to
        }
        diagnostics {
          type
          message
        }
      }
    }
    statusTemplates(search: "") {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

const workflowMigrationMutation = graphql`
  mutation WorkflowMigrationDialogMutation($entityType: String!, $publish: Boolean, $overwrite: Boolean, $scope: StatusScope) {
    workflowMigrate(entityType: $entityType, publish: $publish, overwrite: $overwrite, scope: $scope) {
      id
      published
    }
  }
`;

// The migration refuses these whatever it does next; a name conflict only matters once published.
const ALWAYS_BLOCKING_DIAGNOSTICS = ['MISSING_TEMPLATE', 'REQUEST_ACCESS_OUTCOME_INVALID', 'EXISTING_WORKFLOW'];
const PUBLISH_BLOCKING_DIAGNOSTICS = [...ALWAYS_BLOCKING_DIAGNOSTICS, 'NAME_CONFLICT'];

const isBlocking = (diagnostic: { type: string }, publish: boolean) => (
  publish ? PUBLISH_BLOCKING_DIAGNOSTICS : ALWAYS_BLOCKING_DIAGNOSTICS
).includes(diagnostic.type);

type Translate = (key: string) => string;

// The texts name the statuses the migration reads: the request access ones, or the entity type ones.
// Each key stays a literal t_i18n call so the translation extraction finds it.
const workflowMigrationTexts = (t_i18n: Translate, scope: WorkflowScope) => (scope === 'REQUEST_ACCESS' ? {
  title: t_i18n('Migrate request access statuses'),
  none: t_i18n('There is no request access status to migrate.'),
  intro: t_i18n('The legacy request access statuses become a request access workflow. Existing statuses are reused, so requests keep their current status.'),
  replaceWarning: t_i18n('The current draft of the request access workflow will be replaced by the migrated statuses.'),
  replaceLabel: t_i18n('Replace the current draft of the request access workflow'),
} : {
  title: t_i18n('Migrate statuses'),
  none: t_i18n('There is no status to migrate.'),
  intro: t_i18n('The legacy statuses become a workflow. Existing statuses are reused, so entities keep their current status.'),
  replaceWarning: t_i18n('The current draft of the workflow will be replaced by the migrated statuses.'),
  replaceLabel: t_i18n('Replace the current draft of the workflow'),
});

interface MigrationPreviewProps {
  entityType: string;
  scope: WorkflowScope;
  onClose: () => void;
  onMigrated: () => void;
}

const MigrationPreview = ({ entityType, scope, onClose, onMigrated }: MigrationPreviewProps) => {
  const { t_i18n } = useFormatter();
  const texts = workflowMigrationTexts(t_i18n, scope);
  const [publish, setPublish] = useState(true);
  const [replaceDraftConfirmed, setReplaceDraftConfirmed] = useState(false);
  // Bumped after the outcome statuses are repaired, so the preview is read again.
  const [fetchKey, setFetchKey] = useState(0);
  const { workflowMigrationPreview, statusTemplates } = useLazyLoadQuery<WorkflowMigrationDialogPreviewQuery>(
    workflowMigrationPreviewQuery,
    { entityType },
    { fetchPolicy: 'network-only', fetchKey },
  );
  const [commitMigration, migrating] = useApiMutation<WorkflowMigrationDialogMutation>(workflowMigrationMutation);

  const preview = workflowMigrationPreview?.results.find((result) => result.scope === scope);
  const names = new Map<string, string>();
  statusTemplates?.edges?.forEach((edge) => {
    if (edge?.node) names.set(edge.node.id, edge.node.name);
  });
  const nameOf = (statusId: string) => names.get(statusId) ?? statusId;

  if (!preview) {
    return (
      <>
        <Text variant="content-base" as="p">{texts.none}</Text>
        <DialogActions>
          <Button variant="secondary" onClick={onClose}>{t_i18n('Cancel')}</Button>
        </DialogActions>
      </>
    );
  }

  // A workflow never published is only a draft: the migration may replace it once confirmed.
  const replacesDraft = !preview.hasPublishedVersion && preview.diagnostics.some((diagnostic) => diagnostic.type === 'EXISTING_WORKFLOW');
  const diagnostics = replacesDraft ? preview.diagnostics.filter((diagnostic) => diagnostic.type !== 'EXISTING_WORKFLOW') : preview.diagnostics;
  const blocked = diagnostics.some((diagnostic) => isBlocking(diagnostic, publish)) || (replacesDraft && !replaceDraftConfirmed);
  const states = [...preview.states].sort((a, b) => a.order - b.order);
  // The migrated mesh has one transition per pair of statuses: the sources of a same event are listed together.
  const transitionLines = new Map<string, { event: string; from: string[]; to: string }>();
  preview.transitions.forEach((transition) => {
    const key = `${transition.event}:${transition.to}`;
    const line = transitionLines.get(key) ?? { event: transition.event, from: [], to: nameOf(transition.to ?? '') };
    line.from.push(...transition.from.map(nameOf));
    transitionLines.set(key, line);
  });

  const handleConfirm = () => {
    commitMigration({
      variables: { entityType, publish, overwrite: replacesDraft, scope },
      onCompleted: (_response, errors) => {
        if (errors?.length) return;
        onMigrated();
        onClose();
      },
      // The failure is reported by the mutation hook: the dialog stays open so the choices can be adjusted.
      onError: () => {},
    });
  };

  return (
    <>
      <Text variant="content-base" as="p" style={{ marginBottom: 16 }}>
        {texts.intro}
      </Text>
      {replacesDraft && (
        <div data-testid="workflow-migration-replace-draft" style={{ marginBottom: 8 }}>
          <Alert
            severity="warning"
            title={t_i18n('Warning')}
            description={texts.replaceWarning}
            style={{ marginBottom: 8 }}
          />
          <Checkbox
            label={texts.replaceLabel}
            checked={replaceDraftConfirmed}
            onCheckedChange={(checked) => setReplaceDraftConfirmed(checked === true)}
          />
        </div>
      )}
      {diagnostics.map((diagnostic, index) => (
        <Alert
          key={`${diagnostic.type}-${index}`}
          data-testid="workflow-migration-diagnostic"
          severity={isBlocking(diagnostic, publish) ? 'error' : 'warning'}
          title={isBlocking(diagnostic, publish) ? t_i18n('Blocking') : t_i18n('Warning')}
          description={diagnostic.message}
          style={{ marginBottom: 8 }}
        />
      ))}
      {diagnostics.some((diagnostic) => diagnostic.type === 'REQUEST_ACCESS_OUTCOME_INVALID') && (
        <RequestAccessOutcomeRepair initialState={preview.initialState} statusIds={states.map((state) => state.statusId)} onRepaired={() => setFetchKey((key) => key + 1)} />
      )}
      <Text variant="title-sm" as="h3" style={{ marginTop: 16 }}>{t_i18n('States')}</Text>
      <ul data-testid="workflow-migration-states" style={{ listStyle: 'none', padding: 0, margin: '8px 0' }}>
        {states.map((state) => (
          <li key={state.statusId} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <span>{nameOf(state.statusId)}</span>
            {state.requestAccessOutcome && (
              <Chip
                label={state.requestAccessOutcome === 'APPROVED' ? t_i18n('Approved') : t_i18n('Declined')}
                severity={state.requestAccessOutcome === 'APPROVED' ? 'low' : 'critical'}
              />
            )}
          </li>
        ))}
      </ul>
      <Text variant="title-sm" as="h3" style={{ marginTop: 16 }}>{t_i18n('Transitions')}</Text>
      <ul data-testid="workflow-migration-transitions" style={{ padding: '0 0 0 20px', margin: '8px 0', maxHeight: 200, overflowY: 'auto' }}>
        {[...transitionLines.entries()].map(([key, { event, from, to }]) => (
          <li key={key}>{`${event}: ${from.join(', ')} → ${to}`}</li>
        ))}
      </ul>
      <Switch
        label={t_i18n('Publish immediately')}
        checked={publish}
        onCheckedChange={setPublish}
        wrapperClassName="workflow-migration-publish"
      />
      <DialogActions>
        <Button variant="secondary" onClick={onClose}>{t_i18n('Cancel')}</Button>
        <Button
          data-testid="workflow-migration-confirm-button"
          onClick={handleConfirm}
          disabled={blocked || migrating}
        >
          {t_i18n('Migrate')}
        </Button>
      </DialogActions>
    </>
  );
};

interface WorkflowMigrationDialogProps {
  entityType: string;
  scope: WorkflowScope;
  open: boolean;
  onClose: () => void;
  onMigrated: () => void;
}

const WorkflowMigrationDialog = ({ entityType, scope, open, onClose, onMigrated }: WorkflowMigrationDialogProps) => {
  const { t_i18n } = useFormatter();

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={workflowMigrationTexts(t_i18n, scope).title}
      size="medium"
    >
      <ErrorBoundary>
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <MigrationPreview entityType={entityType} scope={scope} onClose={onClose} onMigrated={onMigrated} />
        </Suspense>
      </ErrorBoundary>
    </Dialog>
  );
};

export default WorkflowMigrationDialog;
