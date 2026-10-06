import React from 'react';
import { huntPackImportMutation, notifyHuntPackImport } from '@components/hunts/HuntPack';
import { HuntPackImportMutation } from '@components/hunts/__generated__/HuntPackImportMutation.graphql';
import XtmHubDialogConnectivityLost from '@components/xtm_hub/dialog/connectivity-lost';
import { PATH_HUNT, PATH_HUNTS } from '@components/common/routes/paths';
import { useNavigate, useParams } from 'react-router';
import { MESSAGING$ } from '../../../relay/environment';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { notifyPayloadErrors } from '../hunts/hunt-mutation-utils';
import Loader from '../../../components/Loader';
import useXtmHubDownloadDocument from '../../../utils/hooks/useXtmHubDownloadDocument';
import { useFormatter } from '../../../components/i18n';

const DeployHuntPack = () => {
  const navigate = useNavigate();
  const { serviceInstanceId, fileId } = useParams();
  const { t_i18n } = useFormatter();

  const [commitImportMutation] = useApiMutation<HuntPackImportMutation>(
    huntPackImportMutation,
    undefined,
    {
      errorMessageMap: {
        FORBIDDEN_ACCESS: t_i18n(
          'You are not allowed to do this because you do not have the rights to create hunts.',
        ),
      },
    },
  );
  const sendImportToBack = (importedFile: File) => {
    commitImportMutation({
      variables: { file: importedFile },
      onCompleted: (data, errors) => {
        if (notifyPayloadErrors(errors)) {
          navigate(PATH_HUNTS);
          return;
        }
        notifyHuntPackImport(t_i18n, data.huntPackImport);
        const hunts = data.huntPackImport?.hunts ?? [];
        navigate(hunts.length === 1 ? PATH_HUNT(hunts[0].id) : PATH_HUNTS);
      },
      onError: () => {
        navigate(PATH_HUNTS);
        MESSAGING$.notifyError(t_i18n('An error occurred while importing the hunt pack'));
      },
    });
  };

  const onDownloadError = () => {
    navigate('/dashboard');
    MESSAGING$.notifyError(
      t_i18n('An error occurred while importing the hunt pack. You have been redirected to home page.'),
    );
  };

  const { dialogConnectivityLostStatus } = useXtmHubDownloadDocument({
    serviceInstanceId,
    fileId,
    onSuccess: sendImportToBack,
    onError: onDownloadError,
  });

  const onConfirm = () => {
    navigate('/redirect/connect-xtm-hub');
  };

  const onCancel = () => {
    navigate(PATH_HUNTS);
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
export default DeployHuntPack;
