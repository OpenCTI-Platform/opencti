import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import Divider from '@mui/material/Divider';
import React from 'react';
import { declineRequestAccessMutation, validateRequestAccessMutation } from '@components/cases/CaseUtils';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS, KNOWLEDGE_KNUPDATE_KNORGARESTRICT } from '../../../../utils/hooks/useGranted';
import ItemStatus from '../../../../components/ItemStatus';
import { useFormatter } from '../../../../components/i18n';
import { CaseRfi_caseRfi$data } from './__generated__/CaseRfi_caseRfi.graphql';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';

interface CaseRfiRequestAccessOverviewProps {
  data: CaseRfi_caseRfi$data;
}

const ProcessingStatusOverview = ({ data }: CaseRfiRequestAccessOverviewProps) => {
  const { t_i18n } = useFormatter();
  let requestAccessData = null;
  let isRequestAccessNew = false;
  const approvedButtonColor = data.requestAccessConfiguration?.approved_status?.template?.color;
  const declineButtonColor = data.requestAccessConfiguration?.declined_status?.template?.color;

  if (data.x_opencti_request_access) {
    requestAccessData = JSON.parse(data.x_opencti_request_access);
    // see RequestAccessAction interface in backend
    // Find action status that correspond to current RFI status.
    const currentActionStatus = requestAccessData.workflowMapping.find((status: any) => status.rfiStatusId === data.status?.id);
    isRequestAccessNew = currentActionStatus && currentActionStatus.actionStatus === 'NEW';
  }

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

  return (
    <Security needs={[KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS, KNOWLEDGE_KNUPDATE_KNORGARESTRICT]}>
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
          {isRequestAccessNew && (
          <div>
            <Button
              color="primary"
              variant="outlined"
              style={{ marginRight: 10, color: approvedButtonColor, borderColor: approvedButtonColor }}
              onClick={onSubmitValidateRequestAccess}
            >
              {t_i18n('Validate')}
            </Button>
            <Button
              color="primary"
              variant="outlined"
              style={{ color: declineButtonColor, borderColor: declineButtonColor }}
              onClick={onSubmitDeclineRequestAccess}
            >
              {t_i18n('Decline')}
            </Button>
          </div>)}
        </div>
        <Divider style={{ marginTop: 20 }}/>
      </Grid>
    </Security>);
};

export default ProcessingStatusOverview;
