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

interface CaseRfiRequestAccessOverviewProps {
  data: CaseRfi_caseRfi$data;
}

// see requestAccess-domain.ts in backend.
export interface RequestAccessActionStatus {
  rfiStatusId: string;
  actionStatus: string;
}

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
  const disabledTooltip = draftContext ? t_i18n('Not available in draft') : t_i18n('You need to be able to edit the RFI and share knowledge');
  return (
    <Grid item xs={12} style={{ marginBottom: 20 }}>
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
