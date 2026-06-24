import React from 'react';
import { playbookImportMutation } from '@components/data/playbooks/PlaybookCreation';
import { PlaybookCreationImportMutation } from '@components/data/playbooks/__generated__/PlaybookCreationImportMutation.graphql';
import XtmHubDialogConnectivityLost from '@components/xtm_hub/dialog/connectivity-lost';
import { useNavigate, useParams } from 'react-router-dom';
import { resolveLink } from '../../../utils/Entity';
import { MESSAGING$ } from '../../../relay/environment';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import Loader from '../../../components/Loader';
import useXtmHubDownloadDocument from '../../../utils/hooks/useXtmHubDownloadDocument';
import { useFormatter } from '../../../components/i18n';

const DeployPlaybook = () => {
  const navigate = useNavigate();
  const { serviceInstanceId, fileId } = useParams();
  const { t_i18n } = useFormatter();

  const [commitImportMutation] = useApiMutation<PlaybookCreationImportMutation>(
    playbookImportMutation,
    undefined,
    {
      errorMessageMap: {
        FORBIDDEN_ACCESS: t_i18n(
          'You are not allowed to do this because you do not have the rights to create playbooks.',
        ),
      },
    },
  );
  const sendImportToBack = (importedFile: File) => {
    commitImportMutation({
      variables: { file: importedFile },
      onCompleted: (data) => {
        navigate(`${resolveLink('Playbook')}/${data.playbookImport}`);
        MESSAGING$.notifySuccess(t_i18n('Playbook successfully imported'));
      },
      onError: () => {
        navigate('/dashboard/data/processing/automation');
        MESSAGING$.notifyError(t_i18n('An error occurred while importing playbook'));
      },
    });
  };

  const onDownloadError = () => {
    navigate('/dashboard');
    MESSAGING$.notifyError(
      t_i18n('An error occurred while importing playbook. You have been redirected to home page.'),
    );
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
    navigate('/dashboard/data/processing/automation');
  };

  return (
    <>
      <XtmHubDialogConnectivityLost
        status={dialogConnectivityLostStatus}
        onConfirm={onConfirm}
        onCancel={onCancel}
      />
      <Loader />
    </>
  );
};
export default DeployPlaybook;
