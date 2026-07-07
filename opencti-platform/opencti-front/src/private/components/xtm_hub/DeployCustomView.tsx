import React from 'react';
import { graphql } from 'react-relay';
import XtmHubDialogConnectivityLost from '@components/xtm_hub/dialog/connectivity-lost';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { DeployCustomViewImportMutation } from '@components/xtm_hub/__generated__/DeployCustomViewImportMutation.graphql';
import { MESSAGING$ } from '../../../relay/environment';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import Loader from '../../../components/Loader';
import useXtmHubDownloadDocument from '../../../utils/hooks/useXtmHubDownloadDocument';
import { useFormatter } from '../../../components/i18n';

const customViewImportMutation = graphql`
  mutation DeployCustomViewImportMutation($targetEntityType: String, $file: Upload!) {
    customViewConfigurationImport(targetEntityType: $targetEntityType, file: $file) {
      id
      targetEntityType
    }
  }
`;

const DeployCustomView = () => {
  const navigate = useNavigate();
  const { serviceInstanceId, fileId } = useParams();
  const [searchParams] = useSearchParams();
  const targetEntityTypes = searchParams.getAll('targetEntityType');
  const { t_i18n } = useFormatter();

  const [commitImportMutation] = useApiMutation<DeployCustomViewImportMutation>(
    customViewImportMutation,
    undefined,
    {
      errorMessageMap: {
        FORBIDDEN_ACCESS: t_i18n(
          'You are not allowed to do this because you do not have the rights to create custom views.',
        ),
      },
    },
  );

  const importForEntityType = (
    importedFile: File,
    targetEntityType: string | null,
  ) => new Promise<{ id: string; targetEntityType: string }>((resolve, reject) => {
    commitImportMutation({
      variables: { targetEntityType, file: importedFile },
      onCompleted: (data) => {
        resolve({
          id: data.customViewConfigurationImport.id,
          targetEntityType: data.customViewConfigurationImport.targetEntityType,
        });
      },
      onError: (error) => {
        reject(error);
      },
    });
  });

  const sendImportToBack = async (importedFile: File) => {
    const entityTypes = targetEntityTypes.length > 0 ? targetEntityTypes : [null];
    const results = await Promise.allSettled(
      entityTypes.map((entityType: string | null) => importForEntityType(importedFile, entityType)),
    );
    const createdCustomViews = results
      .filter((r): r is PromiseFulfilledResult<{ id: string; targetEntityType: string }> => r.status === 'fulfilled')
      .map((r) => r.value);

    if (createdCustomViews.length === entityTypes.length) {
      MESSAGING$.notifySuccess(t_i18n('Custom view successfully imported'));
      if (createdCustomViews.length === 1) {
        const [created] = createdCustomViews;
        navigate(
          `/dashboard/settings/customization/entity_types/${created.targetEntityType}/custom-views/${created.id}`,
        );
      } else {
        navigate('/dashboard/settings/customization');
      }
    } else {
      navigate('/dashboard/settings/customization');
    }
  };

  const onDownloadError = () => {
    navigate('/dashboard');
    MESSAGING$.notifyError(
      t_i18n('An error occurred while importing custom view. You have been redirected to home page.'),
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
    navigate('/dashboard/settings/customization');
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
export default DeployCustomView;
