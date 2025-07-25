import React, { useContext, useEffect } from 'react';
import { importMutation } from '@components/workspaces/WorkspaceCreation';
import { useNavigate, useParams } from 'react-router-dom';
import { WorkspaceCreationImportMutation } from '@components/workspaces/__generated__/WorkspaceCreationImportMutation.graphql';
import { resolveLink } from '../../../utils/Entity';
import { MESSAGING$ } from '../../../relay/environment';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import Loader from '../../../components/Loader';
import { UserContext } from '../../../utils/hooks/useAuth';

const DeployCustomDashboard = () => {
  const navigate = useNavigate();
  const { settings } = useContext(UserContext);
  const { serviceInstanceId, fileId } = useParams();
  const [commitImportMutation] = useApiMutation<WorkspaceCreationImportMutation>(importMutation);
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
        MESSAGING$.notifyError('An error occured while importing dashboard');
      },
    });
  };
  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await fetch(
          `${settings?.platform_xtmhub_url}/document/get/${serviceInstanceId}/${fileId}`,
          {
            method: 'GET',
            credentials: 'include',
          },
        );

        const blob = await response.blob();
        const file = new File([blob], 'downloaded.json', {
          type: 'application/json',
        });

        sendImportToBack(file);
      } catch (e) {
        navigate('/dashboard');
        MESSAGING$.notifyError('An error occured while importing dashboard. You have been redirected to home page.');
      }
    };
    fetchData();
  }, [serviceInstanceId, fileId]);

  return <Loader />;
};
export default DeployCustomDashboard;
