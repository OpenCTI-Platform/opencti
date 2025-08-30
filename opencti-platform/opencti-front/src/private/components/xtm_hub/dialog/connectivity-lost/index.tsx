import React from 'react';
import XtmHubDialogConnectivityLostAuthorizedRegister from '@components/xtm_hub/dialog/connectivity-lost/AuthorizedRegister';
import XtmHubDialogConnectivityLostUnauthorizedRegister from '@components/xtm_hub/dialog/connectivity-lost/UnauthorizedRegister';

export enum DialogConnectivityLostStatus {
  unknown = 'unknown',
  authorized = 'authorized',
  unauthorized = 'unauthorized',
}

interface Props {
  status: DialogConnectivityLostStatus
  onCancel: () => void
  onConfirm: () => void
}

const XtmHubDialogConnectivityLost: React.FC<Props> = ({ status, onCancel, onConfirm }) => {
  const isAuthorizedDialogOpen = status === DialogConnectivityLostStatus.authorized;
  const isUnauthorizedDialogOpen = status === DialogConnectivityLostStatus.unauthorized;

  return <>
    <XtmHubDialogConnectivityLostAuthorizedRegister
      open={isAuthorizedDialogOpen}
      onCancel={onCancel}
      onConfirm={onConfirm}
    />

    <XtmHubDialogConnectivityLostUnauthorizedRegister
      open={isUnauthorizedDialogOpen}
      onCancel={onCancel}
    />
  </>;
};

export default XtmHubDialogConnectivityLost;
