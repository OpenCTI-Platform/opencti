import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import Alert from '@mui/material/Alert';
import { useFormatter } from '../../../../components/i18n';
import ItemCopy from '../../../../components/ItemCopy';

interface TokenResultViewProps {
  token: string;
  onClose: () => void;
}

const TokenResultView: FunctionComponent<TokenResultViewProps> = ({
  token,
  onClose,
}) => {
  const { t_i18n } = useFormatter();
  // No explicit focus on Close button anymore, handled by ItemCopy focusOnMount
  // useEffect(() => { ... }, []);

  return (
    <div style={{ marginTop: 20 }}>
      <Alert severity="success" variant="outlined" style={{ marginBottom: 20 }}>
        {t_i18n('Token generated successfully')}
      </Alert>

      <Typography variant="body1" gutterBottom>
        {t_i18n('Make sure to copy your new personal access token now. You won\'t be able to see it again!')}
      </Typography>

      <div style={{
        marginTop: 20,
        padding: '15px',
        backgroundColor: 'rgba(255, 255, 255, 0.05)',
        borderRadius: 4,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}
      >
        <div style={{ flexGrow: 1, marginRight: 10, overflow: 'hidden' }}>
          <ItemCopy content={token} variant="inLine" focusOnMount={true} />
        </div>
      </div>

      <div style={{ float: 'right', marginTop: 20 }}>
        <Button
          // ref={closeButtonRef}
          variant="contained"
          color="primary"
          onClick={onClose}
        >
          {t_i18n('Close')}
        </Button>
      </div>
    </div>
  );
};

export default TokenResultView;
