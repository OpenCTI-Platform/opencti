import React, { FunctionComponent, useState } from 'react';
import { useFormatter } from '../../../../components/i18n';
import UserTokenCreationForm from './UserTokenCreationForm';
import TokenResultView from '../../profile/api_tokens/TokenResultView';
import Drawer from '../../common/drawer/Drawer';

interface UserTokenCreationDrawerProps {
  userId: string;
  open: boolean;
  onClose: () => void;
}

const UserTokenCreationDrawer: FunctionComponent<UserTokenCreationDrawerProps> = ({
  userId,
  open,
  onClose,
}) => {
  const { t_i18n } = useFormatter();
  const [generatedToken, setGeneratedToken] = useState<string | null>(null);

  const handleClose = () => {
    setGeneratedToken(null);
    onClose();
  };

  const onSuccess = (token: string) => {
    setGeneratedToken(token);
  };

  return (
    <Drawer
      open={open}
      onClose={handleClose}
      title={generatedToken ? t_i18n('Token details') : t_i18n('Generate a new token')}
      size="medium"
    >
      {generatedToken ? (
        <TokenResultView token={generatedToken} onClose={handleClose} />
      ) : (
        <UserTokenCreationForm userId={userId} onSuccess={onSuccess} onClose={handleClose} />
      )}
    </Drawer>
  );
};

export default UserTokenCreationDrawer;
