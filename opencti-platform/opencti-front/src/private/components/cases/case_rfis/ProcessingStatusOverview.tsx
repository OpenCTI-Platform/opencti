import Grid from '@mui/material/Grid';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import Button from '@common/button/Button';
import Divider from '@mui/material/Divider';
import React from 'react';
import { declineRequestAccessMutation, isWorkflowDrivenRequestAccess, validateRequestAccessMutation } from '@components/cases/CaseUtils';
import ItemStatus from '../../../../components/ItemStatus';
import { useFormatter } from '../../../../components/i18n';
import { CaseRfi_caseRfi$data } from './__generated__/CaseRfi_caseRfi.graphql';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import { WorkflowAllowedTransition, WorkflowTransitionsForEntity } from '../../common/workflow/WorkflowTransitions';
import { WorkflowStatusForEntity } from '../../common/workflow/WorkflowStatus';
import { isWorkflowUiEnabledForType } from '../../common/workflow/workflowFeatureFlag';
import useHelper from '../../../../utils/hooks/useHelper';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';

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
const RequestAccessTransitions = ({ data }: CaseRfiRequestAccessOverviewProps) => {
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();
  const describeOutcome = (transition: WorkflowAllowedTransition) => {
    if (transition.requestAccessOutcome === 'DECLINED') return t_i18n('The applicant will be notified.');
    if (transition.requestAccessOutcome !== 'APPROVED') return undefined;
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
      refreshOnFailure
      transitionButtons={{
        disabledReason: (transition) => (transition.requestAccessOutcome && !userCanAction ? cannotActTooltip(t_i18n, !!draftContext) : undefined),
        effect: describeOutcome,
      }}
    />
  );
};

const WorkflowProcessingStatusOverview = ({ data }: CaseRfiRequestAccessOverviewProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Grid style={{ marginBottom: 20 }} size={12}>
      <Typography
        variant="h3"
        gutterBottom={true}
        style={{ marginTop: 0 }}
      >
        {t_i18n('Processing status')}
      </Typography>
      <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
        <WorkflowStatusForEntity
          data={data}
          entityType={data.entity_type}
          fallback={<ItemStatus status={data.status} />}
        >
          {/* Rendered after the status chip, on the right of the banner */}
          <div style={{ order: 1, marginLeft: 'auto', display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <RequestAccessTransitions data={data} />
            </Security>
          </div>
        </WorkflowStatusForEntity>
      </div>
      <Divider style={{ marginTop: 20 }} />
    </Grid>
  );
};

const LegacyProcessingStatusOverview = ({ data }: CaseRfiRequestAccessOverviewProps) => {
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

const ProcessingStatusOverview = ({ data }: CaseRfiRequestAccessOverviewProps) => {
  const { isFeatureEnable } = useHelper();
  const isWorkflowDriven = isWorkflowUiEnabledForType(data.entity_type, isFeatureEnable) && isWorkflowDrivenRequestAccess(data);
  return isWorkflowDriven ? <WorkflowProcessingStatusOverview data={data} /> : <LegacyProcessingStatusOverview data={data} />;
};

export default ProcessingStatusOverview;
