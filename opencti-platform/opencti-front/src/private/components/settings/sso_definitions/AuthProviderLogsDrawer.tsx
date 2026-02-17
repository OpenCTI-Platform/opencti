import React from 'react';
import { useFragment } from 'react-relay';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import { ssoDefinitionEditionFragment } from '@components/settings/sso_definitions/SSODefinitionEdition';
import { SSODefinitionEditionFragment$key } from '@components/settings/sso_definitions/__generated__/SSODefinitionEditionFragment.graphql';
import AuthProviderLogTab from './AuthProviderLogTab';

interface AuthProviderLogsDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  data: SSODefinitionEditionFragment$key;
}

const AuthProviderLogsDrawer: React.FC<AuthProviderLogsDrawerProps> = ({
  isOpen,
  onClose,
  data,
}) => {
  const { t_i18n } = useFormatter();
  const provider = useFragment(ssoDefinitionEditionFragment, data);

  return (
    <Drawer
      title={`${t_i18n('Logs – ')}${provider.name}`}
      open={isOpen}
      onClose={onClose}
      disableBackdropClose
    >
      <AuthProviderLogTab authLogHistory={provider.authLogHistory} />
    </Drawer>
  );
};

export default AuthProviderLogsDrawer;
