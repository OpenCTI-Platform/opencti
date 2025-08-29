import { useContext, useEffect, useState } from 'react';
import { DialogConnectivityLostStatus } from '@components/xtm_hub/dialog/connectivity-lost';
import XtmHubClient from '../xtm-hub-client';
import { UserContext } from './useAuth';
import useGranted, { SETTINGS_SETMANAGEXTMHUB } from './useGranted';
import useXtmHubUserPlatformToken from './useXtmHubUserPlatformToken';

interface Props {
  serviceInstanceId?: string
  fileId?: string
  onSuccess: (file: File) => void
  onError: (error: unknown) => void
}

interface Return {
  dialogConnectivityLostStatus: DialogConnectivityLostStatus;
}

const useXtmHubDownloadDocument = ({ serviceInstanceId, fileId, onSuccess, onError }: Props): Return => {
  const isGrantedToXtmHub = useGranted([SETTINGS_SETMANAGEXTMHUB]);
  const { settings } = useContext(UserContext);
  const { userPlatformToken } = useXtmHubUserPlatformToken();
  const [dialogConnectivityLostStatus, setDialogConnectivityLostStatus] = useState<DialogConnectivityLostStatus>(DialogConnectivityLostStatus.unknown);

  useEffect(() => {
    const isTryingToDownloadDocument = !!fileId && !!serviceInstanceId;
    const isPlatformRegistered = settings?.xtm_hub_registration_status === 'registered';
    if (isTryingToDownloadDocument && !isPlatformRegistered) {
      if (isGrantedToXtmHub) {
        setDialogConnectivityLostStatus(DialogConnectivityLostStatus.authorized);
      } else {
        setDialogConnectivityLostStatus(DialogConnectivityLostStatus.unauthorized);
      }
      return;
    }

    if (!settings || !userPlatformToken || !serviceInstanceId || !fileId) {
      return;
    }

    const fetchData = async () => {
      try {
        const file = await XtmHubClient.fetchDocument({
          settings,
          serviceInstanceId,
          fileId,
          userPlatformToken,
        });

        onSuccess(file);
      } catch (e) {
        onError(e);
      }
    };

    fetchData();
  }, [settings, serviceInstanceId, fileId, userPlatformToken]);

  return {
    dialogConnectivityLostStatus,
  };
};

export default useXtmHubDownloadDocument;
