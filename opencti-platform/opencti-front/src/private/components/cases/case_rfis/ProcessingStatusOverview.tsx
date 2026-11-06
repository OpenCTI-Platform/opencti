import Grid from '@mui/material/Grid';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import Button from '@common/button/Button';
import Divider from '@mui/material/Divider';
import React from 'react';
import { declineRequestAccessMutation, validateRequestAccessMutation } from '@components/cases/CaseUtils';
import ItemStatus from '../../../../components/ItemStatus';
import { useFormatter } from '../../../../components/i18n';
import { CaseRfi_caseRfi$data } from './__generated__/CaseRfi_caseRfi.graphql';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import { WorkflowAllowedTransition, WorkflowTransitionsForEntity } from '../../common/workflow/WorkflowTransitions';

interface CaseRfiRequestAccessOverviewProps {
  data: CaseRfi_caseRfi$data;
}

// see requestAccess-domain.ts in backend.
export interface RequestAccessActionStatus {
  rfiStatusId: string;
  actionStatus: string;
}

const cannotActTooltip = (t_i18n: (message: string) => string, inDraft: boolean) => {
  return inDraft ? t_i18n('Not available in draft') : t_i18n('You need to be able to edit the RFI and share knowledge');
};

const countRequestedEntities = (requestAccess: string | null | undefined) => {
  try {
    const action: { entities?: string[] } = JSON.parse(requestAccess ?? '{}');
    return action.entities?.length ?? 0;
  } catch {
    return 0;
  }
};

// Decision buttons of an RFI whose request access runs on the workflow engine
export const RequestAccessTransitions = ({ data }: CaseRfiRequestAccessOverviewProps) => {
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();
  const configuration = data.requestAccessConfiguration?.configuration;
  // The Approved and Declined states of the definition are mapped to the configured approved and declined statuses
  const outcomeOf = (transition: WorkflowAllowedTransition) => {
    const targetStatusId = transition.toStatus?.id;
    if (!targetStatusId) return undefined;
    if (targetStatusId === configuration?.approved_status?.id) return 'APPROVED';
    if (targetStatusId === configuration?.declined_status?.id) return 'DECLINED';
    return undefined;
  };
  const describeOutcome = (transition: WorkflowAllowedTransition) => {
    const outcome = outcomeOf(transition);
    if (outcome === 'DECLINED') return t_i18n('The applicant will be notified.');
    if (outcome !== 'APPROVED') return undefined;
    const organization = data.createdBy?.name ?? t_i18n('the requesting organization');
    const count = countRequestedEntities(data.x_opencti_request_access);
    return count === 1
      ? t_i18n('This will share the requested entity with {organization} and notify the applicant.', { values: { organization } })
      : t_i18n('This will share {count} requested entities with {organization} and notify the applicant.', { values: { count, organization } });
  };
  const userCanAction = data.requestAccessConfiguration?.isUserCanAction;
  return (
    <WorkflowTransitionsForEntity
      data={data}
      entityType={data.entity_type}
      transitionButtons={{
        disabledReason: (transition) => (outcomeOf(transition) && !userCanAction ? cannotActTooltip(t_i18n, !!draftContext) : undefined),
        effect: describeOutcome,
      }}
    />
  );
};

const ProcessingStatusOverview = ({ data }: CaseRfiRequestAccessOverviewProps) => {
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();
  const approvedStatus = data.requestAccessConfiguration?.configuration?.approved_status;
  const approvedButtonColor = approvedStatus?.template?.color;
  const declinedStatus = data.requestAccessConfiguration?.configuration?.declined_status;
  const declineButtonColor = declinedStatus?.template?.color;
  const rfiStatus = data.status?.id;
  const isDecisionNotTaken = rfiStatus !== approvedStatus?.id && rfiStatus !== declinedStatus?.id;
  const requestAccessData = data.x_opencti_request_access;
  const onSubmitValidateRequestAccess = () => {
    commitMutation({
      mutation: validateRequestAccessMutation,
      variables: {
        id: data.id,
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess(t_i18n('This request for sharing has been approved'));
      },
      updater: undefined,
      setSubmitting: undefined,
      onError: undefined,
      optimisticResponse: undefined,
      optimisticUpdater: undefined,
    });
  };

  const onSubmitDeclineRequestAccess = () => {
    commitMutation({
      mutation: declineRequestAccessMutation,
      variables: {
        id: data.id,
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess(t_i18n('This request for sharing has been declined'));
      },
      updater: undefined,
      setSubmitting: undefined,
      onError: undefined,
      optimisticResponse: undefined,
      optimisticUpdater: undefined,
    });
  };

  const userCanAction = data.requestAccessConfiguration?.isUserCanAction;
  const disabledTooltip = cannotActTooltip(t_i18n, !!draftContext);
  return (
    <Grid style={{ marginBottom: 20 }} size={12}>
      <Typography
        variant="h3"
        gutterBottom={true}
        style={{ marginTop: 0 }}
      >
        {t_i18n('Processing status')}
      </Typography>
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
      }}
      >
        <ItemStatus
          status={data.status}
          disabled={!data.workflowEnabled && !requestAccessData}
        />
        {!userCanAction && (
          <Tooltip title={disabledTooltip}>
            <div>
              <Button
                disabled
                style={{ marginRight: 10 }}
              >
                {t_i18n('Validate')}
              </Button>
              <Button
                disabled
              >
                {t_i18n('Decline')}
              </Button>
            </div>
          </Tooltip>
        )}
        {isDecisionNotTaken && userCanAction && (
          <div>
            <Button
              variant="secondary"
              style={{ marginRight: 10, color: approvedButtonColor, borderColor: approvedButtonColor }}
              onClick={onSubmitValidateRequestAccess}
            >
              {t_i18n('Validate')}
            </Button>
            <Button
              variant="secondary"
              style={{ color: declineButtonColor, borderColor: declineButtonColor }}
              onClick={onSubmitDeclineRequestAccess}
            >
              {t_i18n('Decline')}
            </Button>
          </div>
        )}
      </div>
      <Divider style={{ marginTop: 20 }} />
    </Grid>
  );
};

export default ProcessingStatusOverview;
