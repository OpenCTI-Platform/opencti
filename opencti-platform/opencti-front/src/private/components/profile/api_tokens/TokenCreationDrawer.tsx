import React, { FunctionComponent, useState } from 'react';
import { useFormatter } from '../../../../components/i18n';
import TokenCreationForm from './TokenCreationForm';
import TokenResultView from './TokenResultView';
import Drawer from '../../common/drawer/Drawer';

interface TokenCreationDrawerProps {
  userId: string;
  open: boolean;
  onClose: () => void;
}

const TokenCreationDrawer: FunctionComponent<TokenCreationDrawerProps> = ({
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
        <TokenResultView
          token={generatedToken}
          onClose={handleClose}
        />
      ) : (
        <>
          <TokenCreationForm
            userId={userId}
            onSuccess={onSuccess}
            onClose={handleClose}
          />
        </>
      )}
    </Drawer>
  );
};

export default TokenCreationDrawer;
