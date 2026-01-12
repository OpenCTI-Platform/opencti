import React, { FunctionComponent, useState } from 'react';
import Drawer from '@mui/material/Drawer';
import { useFormatter } from '../../../../components/i18n';
import TokenCreationForm from './TokenCreationForm';
import TokenResultView from './TokenResultView';

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
      anchor="right"
      elevation={1}
      sx={{ zIndex: 1202 }}
      classes={{ paper: 'drawer-paper' }}
      onClose={handleClose}
    >
      <div style={{ padding: 20 }}>
        {generatedToken ? (
          <>
            <h2>{t_i18n('Token details')}</h2>
            <TokenResultView token={generatedToken} onClose={handleClose} />
          </>
        ) : (
          <>
            <h2>{t_i18n('Generate a new token')}</h2>
            <TokenCreationForm userId={userId} onSuccess={onSuccess} onClose={handleClose} />
          </>
        )}
      </div>
    </Drawer>
  );
};

export default TokenCreationDrawer;
