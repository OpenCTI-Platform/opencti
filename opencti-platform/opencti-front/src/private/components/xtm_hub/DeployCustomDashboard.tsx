import React from 'react';
import { importMutation } from '@components/workspaces/WorkspaceCreation';
import { useNavigate, useParams } from 'react-router-dom';
import { WorkspaceCreationImportMutation } from '@components/workspaces/__generated__/WorkspaceCreationImportMutation.graphql';
import XtmHubDialogConnectivityLost from '@components/xtm_hub/dialog/connectivity-lost';
import { resolveLink } from '../../../utils/Entity';
import { MESSAGING$ } from '../../../relay/environment';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import Loader from '../../../components/Loader';
import useXtmHubDownloadDocument from '../../../utils/hooks/useXtmHubDownloadDocument';
import { useFormatter } from '../../../components/i18n';

const DeployCustomDashboard = () => {
  const navigate = useNavigate();
  const { serviceInstanceId, fileId } = useParams();
  const { t_i18n } = useFormatter();

  const [commitImportMutation] = useApiMutation<WorkspaceCreationImportMutation>(importMutation, undefined, {
    errorMessageMap: {
      FORBIDDEN_ACCESS: t_i18n('You are not allowed to do this because you do not have the rights to create dashboards.'),
    },
  });
  const sendImportToBack = (importedFile: File) => {
    commitImportMutation({
      variables: { file: importedFile },
      onCompleted: (data) => {
        navigate(
          `${resolveLink('Dashboard')}/${data.workspaceConfigurationImport}`,
        );
        MESSAGING$.notifySuccess('Dashboard successfully imported');
      },
      onError: () => {
        navigate('/dashboard');
        MESSAGING$.notifyError('An error occurred while importing dashboard');
      },
    });
  };

  const onDownloadError = () => {
    navigate('/dashboard');
    MESSAGING$.notifyError('An error occurred while importing dashboard. You have been redirected to home page.');
  };

  const { dialogConnectivityLostStatus } = useXtmHubDownloadDocument({
    serviceInstanceId,
    fileId,
    onSuccess: sendImportToBack,
    onError: onDownloadError,
  });

  const onConfirm = () => {
    navigate('/dashboard/settings/experience');
  };

  const onCancel = () => {
    navigate('/dashboard/workspaces/dashboards');
  };

  return <>
    <XtmHubDialogConnectivityLost
      status={dialogConnectivityLostStatus}
      onConfirm={onConfirm}
      onCancel={onCancel}
    />
    <Loader />
  </>;
};
export default DeployCustomDashboard;
